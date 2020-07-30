import os
import logbook

from regipy.hive_types import NTUSER_HIVE_TYPE
from regipy.plugins.plugin import Plugin
from regipy.plugins.ntuser.external.OpenSavePidlMRUParser import \
    (get_opensavepidlmru_entries, get_mrulistex_order)

logger = logbook.Logger(__name__)

OPENSAVEPIDLMRU_PATH = r'\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSavePidlMRU'

class OpenSavePidlMRUPlugin(Plugin):
    NAME = 'opensavepidlmru'
    DESCRIPTION = 'Get OpenSavePidlMRU'
    COMPATIBLE_HIVE = NTUSER_HIVE_TYPE

    def run(self):
        opensave_subkeys = self.registry_hive.get_key(OPENSAVEPIDLMRU_PATH)
        for subkeys in opensave_subkeys.iter_subkeys():
            # if subkeys.name != 'md':
            #     continue

            mrulistex = subkeys.get_value('MRUListEx')
            order_dict = get_mrulistex_order(mrulistex)

            for value in subkeys.get_values():
                if value.name == 'MRUListEx':
                    continue
                entry = get_opensavepidlmru_entries(value.value)
                entry['extention'] = subkeys.name
                entry['order'] = order_dict[value.name]

                self.entries.append(entry)

        if self.as_json:
            return self.entries
