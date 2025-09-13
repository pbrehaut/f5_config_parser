from f5_config_parser.stanza.generic import ConfigStanza
from typing import TYPE_CHECKING, List

if TYPE_CHECKING:
    from f5_config_parser.collection import StanzaCollection


class DataGroupStanza(ConfigStanza):
    """Data group with collection-based dependency resolution"""

    def _discover_dependencies(self, collection: 'StanzaCollection') -> List[str]:
        """Discover dependencies using collection filtering"""
        dependency_paths = []

        # Collect all potential object references from records
        potential_objects = set()

        records = self.parsed_config.get('records')
        if isinstance(records, dict):
            # Add record keys as potential objects
            potential_objects.update(records.keys())

            # Add data values as potential objects
            for record_value in records.values():
                if isinstance(record_value, dict):
                    data_value = record_value.get('data')
                    if data_value:
                        potential_objects.add(data_value)

        # Define search scopes in priority order
        search_scopes = [
            ("ltm", "pool"),
            ("ltm", "virtual"),
            ("ltm", "node"),
            ("ltm", "monitor"),
            ("ltm", "profile"),
            ("ltm", "rule"),
            ("sys", "file"),
        ]

        for obj_name in potential_objects:
            qualified_name = self._apply_partition_if_missing(obj_name)

            for scope in search_scopes:
                object_path = collection.resolve_object_by_name(qualified_name, scope)
                if object_path:
                    dependency_paths.append(object_path)

        return dependency_paths