import re
from netmiko import ConnectHandler
from .base import NetworkAdapter, InventoryResult

class CiscoSmallBusinessAdapter(NetworkAdapter):
    """Cisco SG300/SG350/SG355 adapter using the tested cisco_s300_telnet driver."""
    def __init__(self, *args, connection_method="telnet", **kwargs):
        super().__init__(*args, **kwargs)
        self.connection_method = connection_method
        self.connection = None

    def connect(self):
        device_type = "cisco_s300_telnet" if self.connection_method == "telnet" else "cisco_s300"
        self.connection = ConnectHandler(
            device_type=device_type,
            host=self.host,
            username=self.username,
            password=self.password,
            conn_timeout=self.timeout,
            auth_timeout=self.timeout,
            banner_timeout=self.timeout,
        )
        return self

    @staticmethod
    def _parse_inventory(output):
        block = re.search(r'NAME:\s*"1".*?(?=\n\s*NAME:|\Z)', output, re.IGNORECASE | re.DOTALL)
        if not block:
            return "Unknown", "Unknown"
        text = block.group(0)
        model = re.search(r"PID:\s*(\S+)", text, re.IGNORECASE)
        serial = re.search(r"SN:\s*(\S+)", text, re.IGNORECASE)
        return (serial.group(1) if serial else "Unknown", model.group(1) if model else "Unknown")

    def get_inventory(self):
        inv = self.connection.send_command("show inventory", read_timeout=max(self.timeout, 10))
        system = self.connection.send_command("show system", read_timeout=max(self.timeout, 10))
        serial, model = self._parse_inventory(inv)
        name = re.search(r"System Name:\s*(.+)", system, re.IGNORECASE)
        system_name = name.group(1).strip() if name else "Unknown"
        return InventoryResult(self.host, system_name, serial, model)

    def get_config(self):
        config = self.connection.send_command("show running-config", read_timeout=max(self.timeout, 30))
        match = re.search(r"^\s*hostname\s+([^\s]+)", config, re.MULTILINE | re.IGNORECASE)
        hostname = match.group(1).strip() if match else f"switch_{self.host}"
        safe = re.sub(r"[^\w\-]", "_", hostname)
        return f"{safe}.cfg", config

    def disconnect(self):
        if self.connection:
            self.connection.disconnect()
            self.connection = None
