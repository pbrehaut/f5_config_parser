# f5_config_parser/loaders.py
"""Functions for loading and constructing StanzaCollections from various sources."""

from f5_config_parser.collection import StanzaCollection
from f5_config_parser.certificates.certificate_loader import load_certificates_from_tar


def load_collection_with_certificates(config_path: str, tar_path: str) -> StanzaCollection:
    """Create a StanzaCollection from config file and certificate archive."""
    with open(config_path) as f:
        collection = StanzaCollection.from_config(f.read(), initialise=True)

    certificates = load_certificates_from_tar(tar_path)
    collection += certificates

    collection.initialise_dependencies()
    collection.save_dependency_cache()

    return collection