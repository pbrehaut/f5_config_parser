# f5_config_parser/loaders.py
"""Functions for loading and constructing StanzaCollections from various sources."""

from f5_config_parser.collection import StanzaCollection
from f5_config_parser.certificates.certificate_loader import load_certificates_from_tar


def load_collection_from_archive(
        *,
        archive_path: str,
        config_path: str = None,
        config_text: str = None
) -> StanzaCollection:
    """Create a StanzaCollection from config file and certificate archive.

    Args:
        archive_path: Path to UCS/tar archive containing certificates
        config_path: Path to config file (mutually exclusive with config_text)
        config_text: Config text string (mutually exclusive with config_path)

    Returns:
        Initialised StanzaCollection with certificates
    """
    if (config_path is None) == (config_text is None):
        raise ValueError("Must provide exactly one of config_path or config_text")

    if config_path:
        with open(config_path) as f:
            config_content = f.read()
    else:
        config_content = config_text

    collection = StanzaCollection.from_config(config_content, initialise=True)

    certificates = load_certificates_from_tar(archive_path, load_pem_data=True)
    collection += certificates

    collection.initialise_dependencies()
    collection.save_dependency_cache()

    return collection