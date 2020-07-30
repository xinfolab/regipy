import logbook

from regipy.hive_types import SYSTEM_HIVE_TYPE
from regipy.plugins.plugin import Plugin

logger = logbook.Logger(__name__)

LANMANSERVER_PATH = r'Services\LanmanServer\Shares'


class LanmanServerPlugin(Plugin):
    NAME = 'lanmanserver'
    DESCRIPTION = 'Get shared folder information'
    COMPATIBLE_HIVE = SYSTEM_HIVE_TYPE

    def run(self):
        self.entries = dict()
        shares_registry_path = self.registry_hive.get_control_sets(LANMANSERVER_PATH)
        shares_keys = self.registry_hive.get_key(shares_registry_path[0])

        for values in shares_keys.iter_values():
            data = dict()
            for value in values.value:
                value_split = value.split('=')
                data[value_split[0]] = value_split[1]
            self.entries[values.name] = data

        if self.as_json:
            return self.entries
