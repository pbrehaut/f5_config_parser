from collections import defaultdict
import difflib
import logging
from f5_config_parser.factory import StanzaFactory

# Configure logging for F5 config validation
logger = logging.getLogger(__name__)
if not logger.handlers:
    # Create file handler for logging to file
    file_handler = logging.FileHandler('f5_config_validation.log', mode='w')
    file_handler.setLevel(logging.INFO)

    # Create formatter for log messages
    formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    file_handler.setFormatter(formatter)

    # Add handler to logger
    logger.addHandler(file_handler)
    logger.setLevel(logging.INFO)


def extract_headings(file_content, stanza_header_pattern, f5_stanza_header_pattern):
    """
    Extract and categorize configuration headings into F5-specific and generic lists.

    This function parses configuration file content to identify different types of
    stanza headers, separating F5-specific patterns from generic ones, and counts
    occurrences of each heading type for validation purposes.

    Args:
        file_content (str): Raw configuration file content as string
        stanza_header_pattern (Pattern): Regex pattern for generic stanza headers
        f5_stanza_header_pattern (Pattern): Regex pattern for F5-specific stanza headers

    Returns:
        tuple: (f5_heading_counts dict, invalid_headings set)
            - f5_heading_counts: Dictionary with heading prefixes as keys and counts as values
            - invalid_headings: Set of headings that match generic pattern but not F5 pattern
    """
    f5_headings = []
    generic_headings = []

    lines = file_content.split('\n')
    total_lines = len(lines)

    logger.info(f"Starting heading extraction from {total_lines} lines of configuration")

    # Parse each line to identify stanza headers
    for line_num, line in enumerate(lines, 1):
        line = line.rstrip()

        # Skip empty lines and comments (lines starting with #)
        if not line or line.startswith('#'):
            continue

        # Check if line matches F5-specific stanza header pattern
        f5_match = f5_stanza_header_pattern.match(line)
        if f5_match:
            f5_headings.append(line)

        # Check if line matches generic stanza header pattern
        generic_match = stanza_header_pattern.match(line)
        if generic_match:
            generic_headings.append(line)

    logger.info(f"Found {len(f5_headings)} F5-specific headings and {len(generic_headings)} generic headings")

    # Identify headings that are generic but not F5-specific (potentially invalid)
    invalid_headings = set(generic_headings) - set(f5_headings)

    # Count occurrences of each F5 heading type for validation
    f5_heading_counts = defaultdict(int)
    for heading in f5_headings:
        # Special case: admin-partitions headings use first 2 words as key
        if heading == 'cli admin-partitions {' or heading == 'cli global-settings {':
            f5_heading_counts[tuple(heading.split()[:2])] += 1
        # Headings with exactly 3 words use only the first word as key
        elif len(heading.rstrip('}').split()) == 3:
            f5_heading_counts[tuple(heading.split()[:1])] += 1
        # Default case: use first 2 words as key
        else:
            f5_heading_counts[tuple(heading.split()[:2])] += 1

    logger.info(f"Categorised headings into {len(f5_heading_counts)} unique prefix types")
    if invalid_headings:
        logger.warning(f"Identified {len(invalid_headings)} potentially invalid headings")

    return f5_heading_counts, invalid_headings


def validate_config(config_text, f5_config_obj):
    """
    Validate F5 configuration by comparing original text with parsed object output.

    This function ensures that the parsed configuration object can accurately
    reconstruct the original configuration text. It performs content comparison,
    heading count validation, and duplicate detection to identify parsing errors.

    Args:
        config_text (str): Original F5 configuration text
        f5_config_obj: Parsed F5 configuration object with get_stanzas() method

    Raises:
        ValueError: If configuration content mismatch is detected, includes:
            - Original text length
            - Reconstructed text length
            - Error description
        Exception: If duplicate stanzas are detected based on hash comparison
    """
    # Handle TMOS version comments at the beginning of config files
    # Remove first 2 lines if config starts with version comment
    if config_text.startswith('#'):
        config_text_for_comparison = '\n'.join(config_text.splitlines()[2:])
    else:
        config_text_for_comparison = config_text

    # Reconstruct configuration text from parsed stanzas
    reconstructed_config_text = ''
    for stanza in f5_config_obj:
        reconstructed_config_text += str(stanza)

    # Compare original and reconstructed configuration content
    if reconstructed_config_text.strip() != config_text_for_comparison.strip():
        # Generate unified diff for debugging content mismatches
        original_lines = config_text_for_comparison.strip().splitlines(keepends=True)
        reconstructed_lines = reconstructed_config_text.strip().splitlines(keepends=True)

        diff = difflib.unified_diff(
            original_lines,
            reconstructed_lines,
            fromfile='original_config',
            tofile='reconstructed_config',
            lineterm=''
        )

        # Print diff output for debugging
        logger.error("Configuration content mismatch detected:")
        logger.error(f"Original config length: {len(config_text)} characters")
        logger.error(f"Reconstructed config length: {len(reconstructed_config_text)} characters")

        diff_lines = list(diff)
        if diff_lines:
            logger.error("Detailed diff output:")
            for line in diff_lines:
                logger.error(line.rstrip())

        raise ValueError(
            len(config_text),
            len(reconstructed_config_text),
            "Content mismatch detected between original and reconstructed configuration"
        )
    else:
        logger.info(f"Configuration content match detected {hash(reconstructed_config_text.strip())} == {hash(config_text_for_comparison.strip())}")

    # Validate heading counts between original text and parsed objects
    expected_heading_counts, invalid_headings = extract_headings(
        config_text,
        StanzaFactory.STANZA_HEADER_PATTERN,
        StanzaFactory.F5_STANZA_HEADER_PATTERN
    )

    # Check for duplicate stanzas using set creation
    if len(set(f5_config_obj)) != len(f5_config_obj):
        logger.error(f"Duplicate stanzas detected: {len(f5_config_obj)} total stanzas but only {len(set(f5_config_obj))} unique stanzas")
        raise ValueError(f"Duplicate stanzas detected: expected {len(f5_config_obj)} unique stanzas but found {len(set(f5_config_obj))}")

    logger.info(f"Duplicate validation passed: {len(f5_config_obj)} stanzas, all unique")

    # Log summary of validation process
    logger.info(f"Starting heading count validation for {len(expected_heading_counts)} heading types")
    logger.info(f"Total parsed stanzas: {len(f5_config_obj)}")

    # Track validation results
    validation_passed = True
    total_expected_stanzas = 0
    total_actual_stanzas = 0

    # Check that parsed stanza counts match expected heading counts
    for heading_prefix, expected_count in sorted(expected_heading_counts.items()):
        total_expected_stanzas += expected_count

        # Special handling for cli admin-partitions stanzas
        if heading_prefix == ('cli', 'admin-partitions'):
            matching_stanzas = [
                stanza for stanza in f5_config_obj
                if stanza.prefix == ('cli',) and stanza.name == 'admin-partitions'
            ]
        # Special handling for cli global-settings stanzas
        elif heading_prefix == ('cli', 'global-settings'):
            matching_stanzas = [
                stanza for stanza in f5_config_obj
                if stanza.prefix == ('cli',) and stanza.name == 'global-settings'
            ]
        # Handle 2-word prefixes using filter method
        elif len(heading_prefix) == 2:
            matching_stanzas = f5_config_obj.filter(prefix=heading_prefix)
        # Handle single-word prefixes with direct comparison
        else:
            matching_stanzas = [
                stanza for stanza in f5_config_obj
                if stanza.prefix == heading_prefix
            ]

        actual_count = len(matching_stanzas)
        total_actual_stanzas += actual_count

        # Log count validation results
        if actual_count == expected_count:
            logger.info(
                f"[VALID] Prefix '{' '.join(heading_prefix)}' - "
                f"Expected: {expected_count}, Found: {actual_count}"
            )
        else:
            validation_passed = False
            logger.error(
                f"[MISMATCH] Prefix '{' '.join(heading_prefix)}' - "
                f"Expected: {expected_count}, Found: {actual_count}"
            )

    # Log validation summary
    logger.info(f"Validation summary:")
    logger.info(f"  Total expected stanzas: {total_expected_stanzas}")
    logger.info(f"  Total actual stanzas: {total_actual_stanzas}")
    logger.info(f"  Validation status: {'PASSED' if validation_passed else 'FAILED'}")

    # Report any invalid headings found
    if invalid_headings:
        logger.warning(f"Found {len(invalid_headings)} potentially invalid headings:")
        for heading in sorted(invalid_headings):
            logger.warning(f"  - {heading}")
    else:
        logger.info("No invalid headings detected")