from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from f5_config_parser.collection import StanzaCollection


def collection_to_html(collection: 'StanzaCollection', include_dependencies: bool = True) -> str:
    """
    Generate HTML representation of a StanzaCollection with hyperlinked dependencies.

    Args:
        collection: The StanzaCollection to render
        include_dependencies: If True, include dependency lists with hyperlinks

    Returns:
        Complete HTML document as a string
    """
    # Build a set of all full_paths in this collection for quick lookup
    paths_in_collection = {stanza.full_path for stanza in collection.stanzas}

    html_parts = []

    # HTML header
    html_parts.append("""<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>F5 Configuration</title>
    <style>
        body {
            font-family: 'Courier New', monospace;
            font-size: 13px;
            margin: 20px;
            background-color: #f5f5f5;
        }
        h1 {
            font-size: 29px;
        }
        .stanza {
            background-color: white;
            border: 1px solid #ddd;
            border-radius: 4px;
            padding: 15px;
            margin-bottom: 20px;
            font-size: 13px;
        }
        .stanza-header {
            font-weight: bold;
            color: #333;
            margin-bottom: 10px;
            font-size: 15px;
        }
        .stanza-config {
            background-color: #f8f8f8;
            border-left: 3px solid #4CAF50;
            padding: 10px;
            margin: 10px 0;
            white-space: pre-wrap;
            overflow-x: auto;
        }
        .dependencies {
            margin-top: 15px;
            padding: 10px;
            background-color: #e3f2fd;
            border-radius: 3px;
        }
        .dependencies-title {
            font-weight: bold;
            color: #1976d2;
            margin-bottom: 5px;
        }
        .dependency-list {
            list-style-type: none;
            padding-left: 0;
            margin: 5px 0;
        }
        .dependency-list li {
            padding: 3px 0;
        }
        a {
            color: #1976d2;
            text-decoration: none;
        }
        a:hover {
            text-decoration: underline;
        }
        .external-dependency {
            color: #666;
            font-style: italic;
        }
    </style>
</head>
<body>
    <h1>F5 Configuration</h1>
""")

    # Generate HTML for each stanza
    for stanza in collection.stanzas:
        # Create anchor ID from full_path (replace spaces with hyphens for valid HTML IDs)
        anchor_id = stanza.full_path.replace(' ', '-').replace('/', '_')

        html_parts.append(f'    <div class="stanza" id="{anchor_id}">')
        html_parts.append(f'        <div class="stanza-header">{stanza.full_path}</div>')

        # Add the string representation (configuration content)
        config_str = str(stanza).replace('<', '&lt;').replace('>', '&gt;')
        html_parts.append(f'        <div class="stanza-config">{config_str}</div>')

        # Add dependencies if requested and available
        if include_dependencies and stanza._dependencies is not None:
            dependencies = stanza._dependencies

            if dependencies:
                html_parts.append('        <div class="dependencies">')
                html_parts.append('            <div class="dependencies-title">Dependencies:</div>')
                html_parts.append('            <ul class="dependency-list">')

                for dep_path in sorted(dependencies):
                    dep_anchor_id = dep_path.replace(' ', '-').replace('/', '_')

                    if dep_path in paths_in_collection:
                        # Dependency exists in collection - create hyperlink
                        html_parts.append(f'                <li><a href="#{dep_anchor_id}">{dep_path}</a></li>')
                    else:
                        # Dependency not in collection - plain text
                        html_parts.append(
                            f'                <li><span class="external-dependency">{dep_path}</span></li>')

                html_parts.append('            </ul>')
                html_parts.append('        </div>')

        html_parts.append('    </div>')

    # HTML footer
    html_parts.append("""</body>
</html>""")

    return '\n'.join(html_parts)