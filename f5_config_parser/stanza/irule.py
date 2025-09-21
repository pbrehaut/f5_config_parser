from f5_config_parser.stanza.generic import ConfigStanza
from f5_config_parser.stanza.irule_parser import parse_irule
from typing import TYPE_CHECKING, List, Dict, Any

if TYPE_CHECKING:
    from f5_config_parser.collection import StanzaCollection


class IRuleStanza(ConfigStanza):
    """iRule configuration with Tcl content parsing"""

    def _do_parse(self) -> Dict[str, Any]:
        """Custom parsing for iRules using Tcl parser"""
        return parse_irule(self.config_lines)

    def _discover_dependencies(self, collection: 'StanzaCollection') -> List[str]:
        """Discover dependencies using collection filtering"""
        dependency_paths = []

        # Search unique words in priority order of likelihood
        unique_words = self.parsed_config.get('unique_words', [])

        # Define search scopes in priority order
        search_scopes = [
            ("ltm", "data-group"),
            ("ltm", "pool"),
            ("ltm", "virtual"),
            ("ltm", "node"),
            ("ltm", "monitor"),
            ("ltm", "profile"),
            ("ltm", "rule"),
            ("sys", "file"),
        ]

        for word in unique_words:
            qualified_name = self._apply_partition_if_missing(word)

            for scope in search_scopes:
                object_path = collection.resolve_object_by_name(qualified_name, scope)
                if object_path:
                    dependency_paths.append(object_path)

        return dependency_paths