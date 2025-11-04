from f5_config_parser.stanza.generic import ConfigStanza
from typing import TYPE_CHECKING, List

if TYPE_CHECKING:
    from f5_config_parser.collection import StanzaCollection


class WideIPStanza(ConfigStanza):
    """GTM wide IP with collection-based dependency resolution"""

    def _discover_dependencies(self, collection: 'StanzaCollection') -> List[str]:
        """Discover dependencies using collection filtering"""
        dependency_paths = []

        # Pool dependencies
        pools = self.parsed_config.get('pools')
        if pools and isinstance(pools, dict):
            for pool_name in pools.keys():
                pool_path = collection.resolve_object_by_name(pool_name, ('gtm', 'pool', 'a'))
                if pool_path:
                    dependency_paths.append(pool_path)

        return dependency_paths