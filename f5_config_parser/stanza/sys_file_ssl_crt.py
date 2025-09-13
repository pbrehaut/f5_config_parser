"""Stanza class for sys file ssl-cert configuration entries"""

from f5_config_parser.stanza.generic import ConfigStanza
from typing import TYPE_CHECKING, List

if TYPE_CHECKING:
    from f5_config_parser.collection import StanzaCollection


class SysFileCrtStanza(ConfigStanza):
    """
    Represents a sys file ssl-cert configuration entry from F5 config file.

    These stanzas represent certificate file references in the F5 configuration:

    Example:
        sys file ssl-cert /Common/mycert.crt {
            cache-path /config/filestore/files_d/Common_d/certificate_d/:Common:mycert.crt_12345_1
            revision 1
        }

    Dependencies:
        Each sys file ssl-cert stanza depends on its corresponding certificate object
        from the archive with the same name but different prefix:
        - Config stanza: sys file ssl-cert /Common/mycert.crt
        - Certificate object: certificate object /Common/mycert.crt
    """

    def _discover_dependencies(self, collection: 'StanzaCollection') -> List[str]:
        """
        Discover certificate object dependencies using direct name mapping.

        Unlike other stanza types that parse config values to find dependency names,
        sys file ssl-cert stanzas have a direct 1:1 relationship with certificate objects.

        The dependency relationship is:
        - sys file ssl-cert /Common/mycert.crt (this stanza)
        - depends on: certificate object /Common/mycert.crt (from archive)

        We use self.name directly because:
        1. The stanza name IS the certificate name (no parsing needed)
        2. The certificate object has the same name but different prefix
        3. This creates a direct link between config entry and archive object

        Args:
            collection: StanzaCollection containing both config stanzas and certificate objects

        Returns:
            List of dependency paths, typically one certificate object path
        """
        dependency_paths = []

        # Direct name-to-name mapping: use this stanza's name to find certificate object
        # Example: self.name = "/Common/mycert.crt"
        # Looks for: certificate object /Common/mycert.crt
        cert_object_path = collection.resolve_object_by_name(
            self.name,  # Use stanza name directly (no config parsing needed)
            ('certificate', 'object')  # Look in certificate object prefix
        )

        if cert_object_path:
            dependency_paths.append(cert_object_path)

        return dependency_paths