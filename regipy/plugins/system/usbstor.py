import logbook

from regipy.hive_types import SYSTEM_HIVE_TYPE
from regipy.plugins.plugin import Plugin

logger = logbook.Logger(__name__)

USBSTOR_PATH = r'Enum\USBSTOR'


class UsbStorPlugin(Plugin):
    NAME = 'usbstor'
    DESCRIPTION = 'Get usb'
    COMPATIBLE_HIVE = SYSTEM_HIVE_TYPE

    def run(self):
        self.entries = dict()
        usb_registry_path = self.registry_hive.get_control_sets(USBSTOR)
        hardware_subkeys = self.registry_hive.get_key(usb_registry_path[0])

        for subkeys in hardware_subkeys.iter_subkeys():
            data = dict()
            for subkey in subkeys.iter_subkeys():
                value_list = subkey.get_values(as_json=True)
                for value in value_list:
                    data[value.name] = value.value
                self.entries[subkey.name] = data

        if self.as_json:
            return self.entries
