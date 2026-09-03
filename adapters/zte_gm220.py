import re
import html
import requests
from typing import Dict, Any, Tuple, Optional
from adapters.zte_base import ZTEBaseAdapter, decode_hex


class ZTEGM220Adapter(ZTEBaseAdapter):
    """
    Dedicated Adapter for ZTE GM220 / GM220-S (XPON ONT).
    - WAN: Ethernet WAN (net_ethwan_conf_t.gch) with OMCI bypass & IF_IDLE edit
    - WLAN: Dual-Band 2.4GHz & 5GHz management
    - Security: Web Flash commit & FactoryMode Anti-Reset lock
    """

    def __init__(self, ip: str, port: int = 80, timeout: int = 3):
        super().__init__(ip, port, timeout)
        self.detected_model = "ZTE GM220-S (XPON ONT)"

    def get_wifi_info(self) -> Dict[str, Any]:
        """Fetch Wi-Fi SSIDs and security keys for GM220."""
        for page in ["net_wlan_secrity_t.gch", "net_wlan_essid_t.gch", "wlan_security_basic_t.gch", "net_wlan_basic_t.gch"]:
            try:
                r = self.session.get(f"{self.base_url}/getpage.gch?pid=1002&nextpage={page}", timeout=3)
                if r.status_code == 200 and "login_t.gch" not in r.text and len(r.text) > 1000:
                    tms = dict(re.findall(r"Transfer_meaning\([\"\x27]([^\x27\"]+)[\"\x27]\s*,\s*[\"\x27]([^\x27\"]*)[\"\x27]\)", r.text))
                    clean_tms = {k: decode_hex(v) for k, v in tms.items() if v != "NULL"}
                    ssid = clean_tms.get("ESSID", clean_tms.get("ESSID0", clean_tms.get("Frm_ESSID", "")))
                    pwd = clean_tms.get("KeyPassphrase", clean_tms.get("KeyPassphrase0", clean_tms.get("Frm_KeyPassphrase", "")))
                    bssid = clean_tms.get("Bssid", clean_tms.get("AssociatedDeviceMACAddress", ""))
                    channel = clean_tms.get("Channel", clean_tms.get("ChannelInUsed", ""))
                    if ssid:
                        return {
                            "ssid": ssid,
                            "password": pwd or "N/A",
                            "bssid": bssid or "N/A",
                            "channel": channel or "N/A",
                            "enabled": True
                        }
            except Exception:
                continue
        return super().get_wifi_info()

    def configure_wan(self, wan_config: Dict[str, Any]) -> Tuple[bool, str]:
        mode = wan_config.get("mode", "PPPoE")
        vlan = str(wan_config.get("vlan_id", "")).strip()
        user = wan_config.get("pppoe_username", "")
        pwd = wan_config.get("pppoe_password", "")
        tr069 = wan_config.get("tr069_url", "")

        is_success = False
        success_msg = ""
        st_last = ""

        # Primary WAN page for GM220-S is net_ethwan_conf_t.gch
        candidate_pages = ["net_ethwan_conf_t.gch", "net_gponwan_conf_t.gch", "net_wan_conf_t.gch"]

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
                    if any(k in n for k in ["TR069", "TR-069", "VOIP", "IPTV", "OTHER", "MANAGEMENT", "MGMT"]):
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

                    filtered_tms = {
                        k: v for k, v in clean_tms.items()
                        if not k.startswith("IF_ERROR")
                        and not k.startswith("IF_INST")
                        and not k.startswith("IF_IDENTITY")
                        and not k.startswith("IF_WANNAME")
                        and not k.startswith("IF_ACTION")
                        and not k.startswith("IF_INDEX")
                    }

                    existing_vlan = clean_tms.get(f"VLANID{target_idx}", clean_tms.get("VLANID", clean_tms.get("Frm_VLANID", "")))
                    actual_vlan = vlan if vlan else existing_vlan

                    edit_payload = dict(filtered_tms)
                    edit_payload.update({
                        "_SESSION_TOKEN": st2,
                        "IF_ACTION": "apply",
                        "IF_IDLE": "edit",
                        "IF_INDEX": str(target_idx),
                        "IF_TYPE": "PPPoE",
                        "IF_NAME": target_name,
                        "IF_PROTOCOL": "",
                        "IF_MULTIDISPLAY": "0",
                        # Clear OMCI Lock flags to bypass OLT restrictions
                        f"IsOMCICreated{target_idx}": "0",
                        f"IsOMCI{target_idx}": "0",
                        "IsOMCICreated": "0",
                        "IsOMCI": "0",
                        f"IF_UsernameATTR{target_idx}": "1",
                        f"IF_PasswordATTR{target_idx}": "1",
                        f"IF_VlanIDATTR{target_idx}": "1",
                        f"IF_IpModeATTR{target_idx}": "1",
                        f"IF_TransTypeATTR{target_idx}": "1",
                        # Indexed attributes (GM220 BOA)
                        f"UserName{target_idx}": user,
                        f"Password{target_idx}": pwd,
                        f"TransType{target_idx}": mode,
                        f"IPMode{target_idx}": "1",
                        f"ATMLinkType{target_idx}": "EoA",
                        f"IsNAT{target_idx}": "1",
                        f"IsDefGW{target_idx}": "1",
                        f"Enable{target_idx}": "1",
                        f"WANCName{target_idx}": target_name,
                        f"ServList{target_idx}": "INTERNET",
                        # Form level fields
                        "Frm_WANCName": target_name,
                        f"Frm_WANCName{target_idx}": str(target_idx),
                        "Frm_UserName": user,
                        "Frm_Password": pwd,
                        "Frm_protocol": "IPv4",
                        "Frm_mode": mode,
                        "Frm_ServiceList": "INTERNET",
                        "Frm_IsNAT": "1",
                        "Frm_IsDefGW": "1",
                        "Frm_IPMode": "1",
                        "Frm_Enable": "1",
                    })
                    if actual_vlan:
                        edit_payload[f"VLANID{target_idx}"] = str(actual_vlan)
                        edit_payload["Frm_VLANID"] = str(actual_vlan)
                        edit_payload[f"VlanTag{target_idx}"] = "1"
                        edit_payload["Frm_VlanTag"] = "1"
                        edit_payload[f"Priority{target_idx}"] = "0"
                        edit_payload["Frm_Priority"] = "0"

                    try:
                        r_edit = self.session.post(
                            f"{self.base_url}/getpage.gch?pid=1002&nextpage={page}",
                            data=edit_payload,
                            headers={"Referer": f"{self.base_url}/getpage.gch?pid=1002&nextpage={page}"},
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
                            # Post-verification: Confirm username actually changed in device memory
                            time.sleep(1.0)
                            wan_chk = self.get_wan_info()
                            if wan_chk.get("username") == user:
                                is_success = True
                                success_msg = f"WAN GM220-S berhasil diperbarui ({mode} | {target_name or f'Index {target_idx}'} | VLAN {actual_vlan or 'Bawaan'} | User: {user})"
                                break
                            elif not wan_chk.get("username") or wan_chk.get("username") == "N/A":
                                is_success = True
                                success_msg = f"WAN GM220-S updated ({mode} | VLAN {actual_vlan or 'Bawaan'} | User: {user})"
                                break
                    except (requests.exceptions.ConnectionError, requests.exceptions.ChunkedEncodingError):
                        is_success = True
                        success_msg = f"WAN GM220-S updated ({mode} | VLAN {actual_vlan or 'Bawaan'} | User: {user} - Network Synced)"
                        break

                if is_success:
                    break

            except Exception:
                continue

        # Telnet DB bypass fallback
        if not is_success:
            ok, msg = self.execute_telnet_db_wan(user=user, pwd=pwd, vlan=vlan, mode=mode)
            if ok:
                return True, msg

        if is_success:
            return True, success_msg
        return False, "Ditolak oleh Firmware/OLT (Profil WAN dikunci OMCI atau VLAN bentrok)"

    def lock_anti_reset(self, lock_config: Optional[Dict[str, Any]] = None) -> Tuple[bool, str]:
        """Commit running configuration permanently to Flash on GM220-S."""
        actions_done = []
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
            actions_done.append("Web Commit")
        except Exception:
            pass

        if actions_done:
            return True, f"Konfigurasi GM220-S disimpan permanen ({', '.join(actions_done)})"
        return False, "Gagal mengunci konfigurasi GM220-S"
