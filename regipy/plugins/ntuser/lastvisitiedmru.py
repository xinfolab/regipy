import logbook
import struct

from regipy.exceptions import RegistryKeyNotFoundException
from regipy.hive_types import NTUSER_HIVE_TYPE
from regipy.plugins.plugin import Plugin


logger = logbook.Logger(__name__)

LASTVISITIEDMRU_PATH = r'\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\LastVisitedPidlMRU'


class LastVisitiedMRUPlugin(Plugin):
    NAME = 'lastvisitedmru'
    DESCRIPTION = 'Get LastVisitiedMRU'
    COMPATIBLE_HIVE = NTUSER_HIVE_TYPE

    def run(self):
        try:
            subkeys = self.registry_hive.get_key(LASTVISITIEDMRU_PATH)
        except RegistryKeyNotFoundException as ex:
            logger.error(f'Could not find {self.NAME} plugin data at: {LASTVISITIEDMRU_PATH}: {ex}')
            return None

        for value in subkeys.iter_values(as_json=self.as_json):
            if value.name == 'MRUListEx':
                continue

            offset_str_end = bytes.fromhex(value.value).find(b'\x00\x00')
            if offset_str_end < 0:
                continue
            try:
                docname = bytes.fromhex(value.value)[:offset_str_end + 1].decode('utf-16')
            except UnicodeDecodeError as e:
                docname = bytes.fromhex(value.value)[:offset_str_end].decode('utf-16le', 'replace')

            self.entries.append(docname)

        if self.as_json:
            return self.entries
