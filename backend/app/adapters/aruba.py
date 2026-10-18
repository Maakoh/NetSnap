import re
import xml.etree.ElementTree as ET
from urllib.parse import quote
import requests
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5
from .base import NetworkAdapter, InventoryResult

UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/135.0.0.0"

class ArubaInstantOnAdapter(NetworkAdapter):
    """Aruba Instant On 1930 Web UI adapter based on the tested local workflow."""
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.session = None
        self.document_root = None
        self.initial_location = None

    def _get(self, url, **kwargs):
        kwargs.setdefault("timeout", self.timeout)
        response = self.session.get(url, **kwargs)
        response.raise_for_status()
        return response

    def connect(self):
        if not re.match(r"^[0-9a-zA-Z.\-]+$", self.host):
            raise ValueError("Invalid IP/hostname")
        self.session = requests.Session()
        for key, value in {"activeLangId":"english", "firstWelcomeBanner":"true", "userName":self.username}.items():
            self.session.cookies.set(key, value, domain=self.host, path="/")

        r = self._get(f"http://{self.host}", headers={"User-Agent": UA}, allow_redirects=False)
        location = r.headers.get("Location", "")
        match = re.match(r"^/([^/]+)/", location)
        if not match:
            raise ValueError("Aruba document root not found")
        self.document_root, self.initial_location = match.group(1), location

        login_page = self._get(
            f"http://{self.host}{location}",
            headers={"User-Agent": UA, "Accept":"text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"},
        )
        if "inputUsername" not in login_page.text:
            raise ValueError("Aruba Instant On login page not detected")

        # Important: this endpoint is intentionally outside document_root on tested 1930 firmware.
        enc = self._get(
            f"http://{self.host}/device/wcd?{{EncryptionSetting}}",
            headers={
                "Accept":"application/xml, text/xml, */*; q=0.01", "User-Agent":UA,
                "X-Requested-With":"XMLHttpRequest",
                "Referer":f"http://{self.host}/{self.document_root}/hpe/config/login.htm",
            },
        ).text
        rsa = re.search(r"<rsaPublicKey>(.+)</rsaPublicKey>", enc, re.DOTALL)
        token = re.search(r"<loginToken>(.+)</loginToken>", enc, re.DOTALL)
        enabled = re.search(r"<passwEncryptEnable>(.+)</passwEncryptEnable>", enc, re.DOTALL)
        if not all((rsa, token, enabled)):
            raise ValueError("Aruba encryption settings incomplete")

        credential = f"user={quote(self.username)}&password={quote(self.password)}&ssd=true&token={token.group(1)}&"
        if enabled.group(1) == "1":
            key = RSA.import_key(rsa.group(1))
            credential = PKCS1_v1_5.new(key).encrypt(credential.encode()).hex()

        auth = self._get(
            f"http://{self.host}/{self.document_root}/hpe/config/system.xml?action=login&cred={credential}",
            headers={"User-Agent":UA, "Referer":f"http://{self.host}/{self.document_root}/hpe/config/login.htm"},
        ).text
        status = re.search(r"<statusString>(.+)</statusString>", auth, re.DOTALL)
        if not status or status.group(1) != "OK":
            raise ValueError("Login failed")

        self._get(
            f"http://{self.host}/{self.document_root}/hpe/device/authenticate_user.xml",
            headers={"User-Agent":UA, "Referer":f"http://{self.host}/{self.document_root}/hpe/home.htm"},
        )
        return self

    def get_inventory(self):
        r = self._get(
            f"http://{self.host}/{self.document_root}/hpe/wcd?{{SystemGlobalSetting}}",
            headers={"User-Agent":UA, "Accept":"application/xml, text/xml, */*; q=0.01", "X-Requested-With":"XMLHttpRequest"},
        )
        root = ET.fromstring(r.text)
        system = root.find(".//SystemGlobalSetting")
        if system is None:
            raise ValueError("SystemGlobalSetting not found")
        name = (system.findtext("systemName") or "Unknown").strip() or "Unknown"
        serial = (system.findtext("serialNumber") or "Unknown").strip() or "Unknown"
        description = (system.findtext("systemDescription") or "").strip()
        match = re.search(r"\b(JL\d+[A-Z])\b", description, re.IGNORECASE)
        model = match.group(1).upper() if match else "Unknown"
        return InventoryResult(self.host, name, serial, model)

    def get_config(self):
        r = self._get(
            f"http://{self.host}/{self.document_root}/hpe/http_download?action=2&ssd=4",
            headers={"User-Agent":UA, "Referer":f"http://{self.host}/{self.document_root}/hpe/home.htm"},
        )
        content = r.text
        hostname = None
        try:
            root = ET.fromstring(content)
            elem = root.find(".//hostname")
            if elem is not None and elem.text:
                hostname = elem.text.strip()
        except ET.ParseError:
            pass
        if not hostname:
            match = re.search(r"^\s*hostname\s+([^\s]+)", content, re.MULTILINE | re.IGNORECASE)
            hostname = match.group(1).strip() if match else f"switch_{self.host}"
        safe = re.sub(r"[^\w\-]", "_", hostname)
        return f"{safe}.cfg", content

    def disconnect(self):
        if self.session:
            self.session.close()
            self.session = None
