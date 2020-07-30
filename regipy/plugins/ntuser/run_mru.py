import logbook

from regipy.exceptions import RegistryKeyNotFoundException
from regipy.hive_types import NTUSER_HIVE_TYPE
from regipy.plugins.plugin import Plugin


logger = logbook.Logger(__name__)

RUNMRU_PATH = r'\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU'


class RunMRUPlugin(Plugin):
    NAME = 'runmru'
    DESCRIPTION = 'Get RunMRU'
    COMPATIBLE_HIVE = NTUSER_HIVE_TYPE

    def run(self):
        try:
            subkeys = self.registry_hive.get_key(RUNMRU_PATH)
        except RegistryKeyNotFoundException as ex:
            logger.error(f'Could not find {self.NAME} plugin data at: {RUNMRU_PATH}: {ex}')
            return None

        for value in subkeys.iter_values(as_json=self.as_json):
            if value.name == 'MRUList':
                continue

            self.entries.append({
                'name': value.name,
                'value': value.value
            })

        if self.as_json:
            return self.entries
