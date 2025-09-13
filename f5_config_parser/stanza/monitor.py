from f5_config_parser.stanza.generic import ConfigStanza
from typing import TYPE_CHECKING, List

if TYPE_CHECKING:
    from f5_config_parser.collection import StanzaCollection


class HTTPSMonitorStanza(ConfigStanza):
    """HTTPS monitor with collection-based dependency resolution"""

    def _discover_dependencies(self, collection: 'StanzaCollection') -> List[str]:
        """Discover dependencies using collection filtering"""
        dependency_paths = []

        # Parent profile dependency
        defaults_from = self.parsed_config.get('defaults-from')
        if defaults_from:
            parent_path = collection.resolve_object_by_name(defaults_from, self.prefix)
            if parent_path:
                dependency_paths.append(parent_path)

        ssl_profile = self.parsed_config.get('ssl-profile')
        if ssl_profile:
            parent_path = collection.resolve_object_by_name(ssl_profile, ('ltm', 'profile', 'server-ssl'))
            if parent_path:
                dependency_paths.append(parent_path)

        return dependency_paths
