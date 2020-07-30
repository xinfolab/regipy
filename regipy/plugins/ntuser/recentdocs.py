import logbook
import struct

from regipy.exceptions import RegistryKeyNotFoundException
from regipy.hive_types import NTUSER_HIVE_TYPE
from regipy.plugins.plugin import Plugin


logger = logbook.Logger(__name__)

RECENTDOCS_PATH = r'\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs'


class RecentDocsPlugin(Plugin):
    NAME = 'recentdocs'
    DESCRIPTION = 'Get RunMRU'
    COMPATIBLE_HIVE = NTUSER_HIVE_TYPE

    def run(self):
        try:
            recentdocs_subkeys = self.registry_hive.get_key(RECENTDOCS_PATH)
        except RegistryKeyNotFoundException as ex:
            logger.error(f'Could not find {self.NAME} plugin data at: {RECENTDOCS_PATH}: {ex}')
            return None

        for subkeys in recentdocs_subkeys.iter_subkeys():
            data = dict()
            value_list = subkeys.get_values(as_json=True)
            for value in value_list:
                if value.name.find('MRUListEx') >= 0:
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
