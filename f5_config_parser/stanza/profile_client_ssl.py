from f5_config_parser.stanza.generic import ConfigStanza
from typing import TYPE_CHECKING, List

if TYPE_CHECKING:
    from f5_config_parser.collection import StanzaCollection


class SslProfileStanza(ConfigStanza):
    """Client SSL profile with collection-based dependency resolution"""

    def _discover_dependencies(self, collection: 'StanzaCollection') -> List[str]:
        """Discover dependencies using collection filtering"""
        dependency_paths = []

        # Certificate dependency
        cert = self.parsed_config.get('cert')
        if cert:
            cert_path = collection.resolve_object_by_name(cert, ("sys", "file", "ssl-cert"))
            if cert_path:
                dependency_paths.append(cert_path)

        # Chain certificate dependency
        chain = self.parsed_config.get('chain')
        if chain:
            chain_path = collection.resolve_object_by_name(chain, ("sys", "file", "ssl-cert"))
            if chain_path:
                dependency_paths.append(chain_path)

        # ca-file dependency
        ca_file = self.parsed_config.get('ca-file')
        if ca_file:
            ca_file_path = collection.resolve_object_by_name(ca_file, ("sys", "file", "ssl-cert"))
            if ca_file_path:
                dependency_paths.append(ca_file_path)

        # Parent profile dependency
        defaults_from = self.parsed_config.get('defaults-from')
        if defaults_from:
            parent_path = collection.resolve_object_by_name(defaults_from, self.prefix)
            if parent_path:
                dependency_paths.append(parent_path)

        # Validate cert-key-chain matches top-level cert/chain
        cert_key_chain = self.parsed_config.get('cert-key-chain')
        if isinstance(cert_key_chain, dict):
            for chain_config in cert_key_chain.values():
                if isinstance(chain_config, dict):
                    chain_cert = chain_config.get('cert')
                    chain_chain = chain_config.get('chain')
                    if cert:
                        if chain_cert and chain_cert != cert:
                            raise ValueError(f"cert-key-chain cert '{chain_cert}' does not match top-level cert '{cert}'")
                    if chain:
                        if chain_chain and chain_chain != chain:
                            raise ValueError(
                                f"cert-key-chain chain '{chain_chain}' does not match top-level chain '{chain}'")

        return dependency_paths
