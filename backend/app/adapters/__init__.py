from .aruba import ArubaInstantOnAdapter
from .cisco import CiscoSmallBusinessAdapter

ADAPTERS = {
    "aruba": ArubaInstantOnAdapter,
    "cisco": CiscoSmallBusinessAdapter,
}
