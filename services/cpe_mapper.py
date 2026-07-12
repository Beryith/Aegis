"""
Mapping des services détectés par Nmap vers des identifiants CPE (Common Platform Enumeration).
Permet une recherche CVE précise au lieu d'une recherche par mot-clé bruitée.
"""
import re

SERVICE_CPE_MAP = {
    "ssh": ("openbsd", "openssh"),
    "http": ("apache", "http_server"),
    "https": ("apache", "http_server"),
    "ftp": ("proftpd", "proftpd"),
    "postgresql": ("postgresql", "postgresql"),
    "mysql": ("mysql", "mysql"),
    "mongodb": ("mongodb", "mongodb"),
    "redis": ("redis", "redis"),
    "smtp": ("postfix", "postfix"),
    "telnet": ("gnu", "inetutils"),
    "rdp": ("microsoft", "remote_desktop_services"),
    "vnc": ("realvnc", "vnc_connect"),
    "dns": ("isc", "bind"),
    "domain": ("isc", "bind"),
    "ldap": ("openldap", "openldap"),
    "smb": ("samba", "samba"),
    "microsoft-ds": ("samba", "samba"),
    "nfs": ("linux", "linux_kernel"),
    "snmp": ("net-snmp", "net-snmp"),
    "nginx": ("nginx", "nginx"),
    "tomcat": ("apache", "tomcat"),
    "elasticsearch": ("elastic", "elasticsearch"),
    "docker": ("docker", "docker"),
}

PRODUCT_HINTS = {
    "apache": ("apache", "http_server"),
    "nginx": ("nginx", "nginx"),
    "openssh": ("openbsd", "openssh"),
    "iis": ("microsoft", "iis"),
    "postfix": ("postfix", "postfix"),
    "dovecot": ("dovecot", "dovecot"),
    "proftpd": ("proftpd", "proftpd"),
    "vsftpd": ("vsftpd_project", "vsftpd"),
    "mariadb": ("mariadb", "mariadb"),
}

def extract_version(version_string: str) -> str:
    if not version_string:
        return ""
    match = re.search(r'(\d+\.\d+(?:\.\d+)?)', version_string)
    if match:
        return match.group(1)
    return ""

def guess_vendor_product(service: str, version_string: str):
    service_lower = (service or "").lower()
    version_lower = (version_string or "").lower()

    for hint, vp in PRODUCT_HINTS.items():
        if hint in version_lower or hint in service_lower:
            return vp

    if service_lower in SERVICE_CPE_MAP:
        return SERVICE_CPE_MAP[service_lower]

    return None

def build_cpe_match_string(service: str, version_string: str) -> str:
    vp = guess_vendor_product(service, version_string)
    version = extract_version(version_string)

    if not vp or not version:
        return ""

    vendor, product = vp
    return f"cpe:2.3:a:{vendor}:{product}:{version}"
