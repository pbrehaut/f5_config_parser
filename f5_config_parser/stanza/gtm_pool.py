from f5_config_parser.stanza.generic import ConfigStanza
from typing import TYPE_CHECKING, List, Dict, Tuple

if TYPE_CHECKING:
    from f5_config_parser.collection import StanzaCollection


class GTMPoolStanza(ConfigStanza):
    """GTM pool with collection-based dependency resolution"""

    def _discover_dependencies(self, collection: 'StanzaCollection') -> List[str]:
        """Discover dependencies using collection filtering"""
        dependency_paths = []

        # Member dependencies (GTM servers)
        members = self.parsed_config.get('members')
        if members and isinstance(members, dict):
            for member_key in members.keys():
                # Split on ':' and take the first part (server name)
                server_name, virtual_server_name = member_key.split(':')
                server_path = collection.resolve_object_by_name(server_name, ('gtm', 'server'))
                virtual_server_path = collection.resolve_object_by_name(virtual_server_name, ('ltm', 'virtual'))
                if server_path:
                    dependency_paths.append(server_path)
                if virtual_server_path:
                    dependency_paths.append(virtual_server_path)

        return dependency_paths

    def _discover_dependency_map(self, collection: 'StanzaCollection') -> Dict[Tuple[str, str], List[str]]:
        """Map config values to their dependencies using tuple keys (attribute_name, value)"""
        dependency_map = {}

        # Member mapping
        members = self.parsed_config.get('members')
        if isinstance(members, dict):
            for member_key in members.keys():
                member_dependencies = []

                # Split on ':' to get server name and virtual server name
                parts = member_key.split(':', 1)
                if len(parts) == 2:
                    server_name = parts[0]
                    virtual_server_name = parts[1]

                    # Resolve the GTM server dependency
                    server_path = collection.resolve_object_by_name(server_name, ('gtm', 'server'))
                    if server_path:
                        member_dependencies.append(server_path)

                    # Add to map using virtual server name as the key
                    if member_dependencies:
                        dependency_map[("members", virtual_server_name)] = member_dependencies

        return dependency_map