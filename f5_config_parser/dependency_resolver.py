from collections import defaultdict
from typing import Generator, Dict, List, Set
from f5_config_parser.collection import StanzaCollection


def generate_waves(all_stanzas: StanzaCollection) -> Generator[List, None, None]:
    """
    Generator that yields dependency waves one at a time.

    Args:
        all_stanzas: Collection of stanzas to process

    Yields:
        List of stanzas in the current wave (stanzas with no dependencies)

    Raises:
        TypeError: If all_stanzas is not a StanzaCollection
    """
    if not isinstance(all_stanzas, StanzaCollection):
        raise TypeError(f"all_stanzas must be a StanzaCollection, got {type(all_stanzas).__name__}")

    while all_stanzas:
        current_wave = []

        for obj in all_stanzas:
            # Check if this stanza has no dependencies in remaining stanzas
            if not any(obj.full_path in x.get_dependencies(all_stanzas) for x in all_stanzas):
                current_wave.append(obj)

        # Second pass: remove all objects from this wave at once
        for obj in current_wave:
            all_stanzas -= obj

        if current_wave:
            yield current_wave
        else:
            # Prevent infinite loop if no progress can be made
            break


def build_waves_structure(all_stanzas: StanzaCollection) -> Dict[int, List]:
    """
    Build the complete waves data structure using the wave generator.

    Args:
        all_stanzas: Collection of stanzas to process

    Returns:
        Dictionary mapping wave numbers to lists of stanzas

    Raises:
        TypeError: If all_stanzas is not a StanzaCollection
    """
    if not isinstance(all_stanzas, StanzaCollection):
        raise TypeError(f"all_stanzas must be a StanzaCollection, got {type(all_stanzas).__name__}")

    waves = defaultdict(list)

    for wave_number, wave_stanzas in enumerate(generate_waves(all_stanzas)):
        waves[wave_number].extend(wave_stanzas)

    return waves