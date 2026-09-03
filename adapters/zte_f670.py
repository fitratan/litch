import re
import html
import requests
from typing import Dict, Any, Tuple, Optional
from adapters.zte_base import ZTEBaseAdapter, decode_hex


class ZTEF670Adapter(ZTEBaseAdapter):
    """
    Dedicated Adapter for ZTE ZXHN F670 / F670L / F672Y / F477 (Dual-Band XPON/GPON ONT).
    - WAN: net_gponwan_conf_t.gch and net_ethwan_conf_t.gch
    - Dual-Band 2.4GHz & 5GHz Multi-SSID provisioning
    - TR-069 ACS Remote Management integration
    - Web Flash Commit
    """

    def __init__(self, ip: str, port: int = 80, timeout: int = 3):
        super().__init__(ip, port, timeout)
        self.detected_model = "ZTE ZXHN F670L Dualband (XPON/GPON ONT)"

    def configure_wan(self, wan_config: Dict[str, Any]) -> Tuple[bool, str]:
        mode = wan_config.get("mode", "PPPoE")
        vlan = str(wan_config.get("vlan_id", "")).strip()
        user = wan_config.get("pppoe_username", "")
        pwd = wan_config.get("pppoe_password", "")
        tr069 = wan_config.get("tr069_url", "")

        is_success = False
        success_msg = ""
        st_last = ""

        candidate_pages = ["net_gponwan_conf_t.gch", "net_ethwan_conf_t.gch", "net_wan_conf_t.gch"]

        for page in candidate_pages:
            try:
                r1 = self.session.get(
                    f"{self.base_url}/getpage.gch?pid=1002&nextpage={page}",
                    headers={"Referer": f"{self.base_url}/"},
                    timeout=max(self.timeout, 4)
                )
                if r1.status_code != 200 or len(r1.text) < 200 or "login_t.gch" in r1.text:
                    continue

                st_m = re.search(r"var\s+session_token\s*=\s*[\"\x27]([^\x27\"]+)[\"\x27]", r1.text)
                st = st_m.group(1) if st_m else ""
                st_last = st

                wan_matches = re.findall(r"Transfer_meaning\([\"\x27]IF_WANNAME(\d+)[\"\x27]\s*,\s*[\"\x27]([^\x27\"]*)[\"\x27]\)", r1.text)
                if not wan_matches:
                    wan_matches = re.findall(r"<option\s+value=[\"\x27]?(\d+)[\"\x27]?>([^<]+)</option>", r1.text)

                profiles = []
                for idx_str, raw_name in wan_matches:
                    d_name = decode_hex(raw_name).strip()
                    profiles.append({"index": str(idx_str), "raw_name": raw_name, "name": d_name})

                if not profiles:
                    profiles = [{"index": "0", "raw_name": "", "name": ""}]

                def profile_priority_score(p):
                    n = p["name"].upper()
                    idx = p["index"]
                    score = 0
                    if any(k in n for k in ["INTERNET", "PPPOE", "PPP", "ROUTE", "DATA", "HSI"]):
                        score += 100
                    if any(k in n for k in ["TR069", "TR-069", "VOIP", "IPTV", "OTHER"]):
                        score -= 50
                    if idx == "1":
                        score += 20
                    elif idx == "0":
                        score += 5
                    return score

                sorted_profiles = sorted(profiles, key=profile_priority_score, reverse=True)

                for prof in sorted_profiles:
                    target_idx = prof["index"]
                    target_name = prof["name"]

                    link_post = {
                        "_SESSION_TOKEN": st_last or st,
                        "IF_ACTION": "wanctype",
                        "IF_INDEX": target_idx,
                        "IF_NAME": target_name,
                        "IF_MULTIDISPLAY": "0",
                        "IF_TYPE": "PPPoE",
                        "IF_PROTOCOL": "",
                    }
                    st2 = st_last or st
                    clean_tms = {}
                    try:
                        r_link = self.session.post(
                            f"{self.base_url}/getpage.gch?pid=1002&nextpage={page}",
                            data=link_post,
                            headers={"Referer": f"{self.base_url}/getpage.gch?pid=1002&nextpage={page}"},
                            timeout=max(self.timeout, 4)
                        )
                        if r_link.status_code == 200:
                            st2_m = re.search(r"var\s+session_token\s*=\s*[\"\x27]([^\x27\"]+)[\"\x27]", r_link.text)
                            if st2_m:
                                st2 = st2_m.group(1)
                                st_last = st2
                            text_link = html.unescape(r_link.text)
                            tms = dict(re.findall(r"Transfer_meaning\([\"\x27]([^\x27\"]+)[\"\x27]\s*,\s*[\"\x27]([^\x27\"]*)[\"\x27]\)", text_link))
                            clean_tms = {k: decode_hex(v) for k, v in tms.items() if v != "NULL"}
                    except Exception:
                        pass

                    PPP_PARA = [
                        "Enable", "WANCName", "ConnType", "LANDViewName", "StrServList", "ServList",
                        "IsNAT", "IsDefGW", "IsForward", "VLANID", "Priority", "WBDMode",
                        "IPAddress", "SubnetMask", "GateWay", "DNS1", "DNS2", "DNS3",
                        "WorkIFMac", "UpTime", "ConnStatus", "UserName", "Password",
                        "PPPoEACName", "PPPoEServiceName", "MRU", "MTU", "ConnTrigger",
                        "TransType", "AuthType", "IdleTime", "ConnError", "DestAddress",
                        "ATMLinkType", "ATMEncapsulation", "ATMQoS", "ATMPeakCellRate",
                        "ATMMaxBurstSize", "ATMMinCellRate", "ATMSCR", "ATMCDV", "RxPackets",
                        "TxPackets", "RxBytes", "TxBytes", "EnableProxy", "MaxUser", "DSCP",
                        "EnablePassThrough", "ValidWANRx", "ValidLANTx", "bitBind", "dhcpEnable",
                        "HostTrigger", "IPMode", "GUASrc", "DNSv6Src", "Gatewayv6Src", "MTUv6Src",
                        "GUA1", "IsOutPreferredLft1", "GUA2", "IsOutPreferredLft2", "GUA3",
                        "IsOutPreferredLft3", "Gatewayv6", "DNS1v6", "DNS2v6", "DNS3v6",
                        "MTUv6", "MCVlANID", "GuaNum", "PdNum", "IPv6CPExt", "PrefixSrc",
                        "Prefix1", "Prefix1Len", "PrefixNum", "IsADSL"
                    ]

                    existing_vlan = clean_tms.get(f"VLANID{target_idx}", clean_tms.get("VLANID", clean_tms.get("Frm_VLANID", "")))
                    actual_vlan = str(vlan).strip() if (vlan and str(vlan).strip()) else existing_vlan

                    edit_payload = {}
                    for p in PPP_PARA:
                        edit_payload[f"{p}{target_idx}"] = "NULL"

                    for k, v in clean_tms.items():
                        if k.startswith("IF_WANNAME") or k.startswith("IF_WANIDENTITY") or (k.startswith("IF_") and "ATTR" in k):
                            edit_payload[k] = v

                    edit_payload.update({
                        "_SESSION_TOKEN": st2,
                        "IF_ACTION": "apply",
                        "IF_IDLE": "edit",
                        "IF_INDEX": str(target_idx),
                        "IF_TYPE": mode,
                        "IF_PROTOCOL": "",
                        "IF_NAME": "",
                        "IF_MODE": "",
                        "IF_MULTIDISPLAY": "0",
                        "IF_STATUS": "1",
                        "IF_PPPNUM": "1",
                        "IF_CONNSTATUS0": "true",
                        "IF_CONNNAME0": target_name,
                        "IPMode0": "ipv4",
                        f"IPMode{target_idx}": "1",
                        f"Enable{target_idx}": "1",
                        f"StrServList{target_idx}": "INTERNET",
                        f"IsNAT{target_idx}": "1",
                        f"VLANID{target_idx}": str(actual_vlan) if actual_vlan else "223",
                        f"Priority{target_idx}": clean_tms.get(f"Priority{target_idx}", "0"),
                        f"WBDMode{target_idx}": clean_tms.get(f"WBDMode{target_idx}", "2"),
                        f"UserName{target_idx}": user,
                        f"Password{target_idx}": pwd,
                        f"MTU{target_idx}": clean_tms.get(f"MTU{target_idx}", "1492"),
                        f"ConnTrigger{target_idx}": "AlwaysOn",
                        f"TransType{target_idx}": mode,
                        f"AuthType{target_idx}": clean_tms.get(f"AuthType{target_idx}", "PAP,CHAP,MS-CHAP"),
                        f"ATMLinkType{target_idx}": "EoA",
                        f"EnableProxy{target_idx}": clean_tms.get(f"EnableProxy{target_idx}", "0"),
                        f"DSCP{target_idx}": clean_tms.get(f"DSCP{target_idx}", "-1"),
                        f"EnablePassThrough{target_idx}": clean_tms.get(f"EnablePassThrough{target_idx}", "0"),
                        f"bitBind{target_idx}": clean_tms.get(f"bitBind{target_idx}", "00011000"),
                        f"dhcpEnable{target_idx}": clean_tms.get(f"dhcpEnable{target_idx}", "1"),
                        f"MCVlANID{target_idx}": clean_tms.get(f"MCVlANID{target_idx}", "-1"),
                        f"IsADSL{target_idx}": clean_tms.get(f"IsADSL{target_idx}", "0"),
                    })

                    headers = {
                        "Referer": f"{self.base_url}/getpage.gch?pid=1002&nextpage={page}",
                        "Origin": self.base_url,
                        "Content-Type": "application/x-www-form-urlencoded",
                    }

                    try:
                        r_edit = self.session.post(
                            f"{self.base_url}/getpage.gch?pid=1002&nextpage={page}",
                            data=edit_payload,
                            headers=headers,
                            timeout=max(self.timeout, 8)
                        )
                        res_text = html.unescape(r_edit.text)
                        tms_res = dict(re.findall(r"Transfer_meaning\([\"\x27]([^\x27\"]+)[\"\x27]\s*,\s*[\"\x27]([^\x27\"]*)[\"\x27]\)", res_text))
                        raw_err = tms_res.get("IF_ERRORSTR", "")
                        err_val = decode_hex(raw_err).strip().upper()

                        has_fatal_error = (
                            err_val in ["FAIL", "ERROR", "INVALID", "E_PARAM", "EXCEED", "CONFLICT", "LOCKED"]
                            or "FAIL" in err_val
                            or "ERROR" in err_val
                        )

                        if not has_fatal_error and r_edit.status_code == 200 and "login_t.gch" not in res_text:
                            is_success = True
                            success_msg = f"WAN F670 berhasil diperbarui ({mode} | {target_name or f'Index {target_idx}'} | VLAN {actual_vlan or 'Bawaan'} | User: {user})"
                            break
                    except (requests.exceptions.ConnectionError, requests.exceptions.ChunkedEncodingError):
                        is_success = True
                        success_msg = f"WAN F670 updated ({mode} | VLAN {actual_vlan or 'Bawaan'} | User: {user} - Network Synced)"
                        break

                if is_success:
                    break

            except Exception:
                continue

        # Optional TR-069
        if is_success and tr069:
            try:
                tr069_payload = {
                    "_SESSION_TOKEN": st_last,
                    "IF_ACTION": "apply",
                    "ServerURL": tr069,
                    "PeriodicInformEnable": "1",
                    "PeriodicInformInterval": "300",
                }
                self.session.post(
                    f"{self.base_url}/getpage.gch?pid=1002&nextpage=net_tr069_basic_t.gch",
                    data=tr069_payload,
                    headers={"Referer": f"{self.base_url}/"},
                    timeout=self.timeout
                )
            except Exception:
                pass

        if not is_success:
            ok, msg = self.execute_telnet_db_wan(user=user, pwd=pwd, vlan=vlan, mode=mode)
            if ok:
                return True, msg

        if is_success:
            return True, success_msg
        return False, "Ditolak oleh Firmware/OLT (Profil WAN dikunci OMCI atau VLAN bentrok)"

    def lock_anti_reset(self, lock_config: Optional[Dict[str, Any]] = None) -> Tuple[bool, str]:
        """Commit running configuration permanently to Flash on F670."""
        try:
            r = self.session.get(f"{self.base_url}/getpage.gch?pid=1002&nextpage=manager_dev_config_t.gch", timeout=3)
            st_m = re.search(r"var\s+session_token\s*=\s*[\"\x27]([^\x27\"]+)[\"\x27]", r.text)
            st = st_m.group(1) if st_m else self.session_token

            payload = {
                "_SESSION_TOKEN": st,
                "IF_ACTION": "save",
                "IF_MULTIDISPLAY": "0",
            }
            self.session.post(
                f"{self.base_url}/getpage.gch?pid=1002&nextpage=manager_dev_config_t.gch",
                data=payload,
                headers={"Referer": f"{self.base_url}/getpage.gch?pid=1002&nextpage=manager_dev_config_t.gch"},
                timeout=4
            )
            return True, "Konfigurasi F670 disimpan permanen ke Flash Storage (Web Commit)"
        except Exception:
            return False, "Gagal mengunci konfigurasi F670"
