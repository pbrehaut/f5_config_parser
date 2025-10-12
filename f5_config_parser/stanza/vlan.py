from f5_config_parser.stanza.generic import ConfigStanza
from typing import TYPE_CHECKING, List

if TYPE_CHECKING:
    from f5_config_parser.collection import StanzaCollection


class VlanStanza(ConfigStanza):
    """"""

    def _discover_dependencies(self, collection: 'StanzaCollection') -> List[str]:
        """Discover dependencies using collection filtering"""
        dependency_paths = []

        interfaces = self.parsed_config.get('interfaces')
        for interface in interfaces:
            parent_path = collection.resolve_object_by_name(interface, ('net', 'trunk'))
            if parent_path:
                dependency_paths.append(parent_path)

        return dependency_paths
