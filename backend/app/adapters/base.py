from abc import ABC, abstractmethod
from dataclasses import dataclass, asdict

@dataclass
class InventoryResult:
    ip: str
    system_name: str = "Unknown"
    serial_number: str = "Unknown"
    model: str = "Unknown"

    def to_dict(self):
        return asdict(self)

class NetworkAdapter(ABC):
    def __init__(self, host: str, username: str, password: str, timeout: int = 8):
        self.host = host.strip()
        self.username = username
        self.password = password
        self.timeout = timeout

    @abstractmethod
    def connect(self): ...

    @abstractmethod
    def get_inventory(self) -> InventoryResult: ...

    @abstractmethod
    def get_config(self) -> tuple[str, str]: ...

    @abstractmethod
    def disconnect(self): ...
