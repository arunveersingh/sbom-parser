# SBOM-Tree

**sbom-tree** is a Python command-line tool that visualizes dependency trees from Software Bill of Materials (SBOM) files in CycloneDX or SPDX JSON formats. It helps developers, security engineers, and DevOps professionals understand and analyze software dependencies by generating clear, customizable dependency trees in ASCII, interactive HTML, or Graphviz DOT formats.

## Features

- **Input Formats**: Supports CycloneDX JSON (preferred) and simple SPDX JSON SBOMs.
- **Output Formats**:
  - **ASCII**: Simple text-based dependency trees printed to stdout (default).
  - **HTML**: Interactive single-file HTML with collapsible nodes, search, and pinned highlighting.
  - **Graphviz DOT**: Output for rendering dependency graphs (e.g., with `dot -Tpng`).

## Installation

No installation is required! Simply download `sbom-tree.py` and run it with Python 3.6 or higher.

### Prerequisites
- Python 3.6+
- For DOT output rendering: Graphviz (optional, to convert `.dot` files to images, e.g., `dot -Tpng out.dot -o out.png`).

### Setup
1. Clone or download this repository:
   ```bash
   git clone https://github.com/<your-username>/sbom-tree.git
   cd sbom-tree
   ```
2. Ensure you have a CycloneDX or SPDX JSON SBOM file to process.

## Usage

Run `sbom-tree.py` with a JSON SBOM file and optional arguments to customize the output.

```bash
python3 sbom-tree.py <sbom-file> [--format <ascii|html|dot>] [--output <file>] [options]
```

### Arguments
- `<sbom-file>`: Path to the CycloneDX or SPDX JSON SBOM file.
- `--format, -f`: Output format (`ascii` (default), `html`, or `dot`).
- `--output, -o`: Output file for HTML or DOT formats (required for HTML).
- `--root`: Specify node ID(s) (bom-ref for CycloneDX, SPDXID for SPDX) to start the tree from. Repeatable.
- `--show-ids`: (ASCII only) Show internal IDs next to node labels.
- `--max-depth`: (ASCII only) Limit the depth of the tree (root=0).
- `--include-dupes`: (ASCII only) Include repeated nodes instead of marking them as seen.

### Examples
1. Generate an ASCII tree with a max depth of 2:
   ```bash
   python3 sbom-tree.py sbom.json --format ascii --max-depth 2
   ```
2. Create an interactive HTML visualization:
   ```bash
   python3 sbom-tree.py sbom.json --format html --output deps.html
   ```
3. Produce a Graphviz DOT file for rendering:
   ```bash
   python3 sbom-tree.py sbom.json --format dot --output deps.dot
   dot -Tpng deps.dot -o deps.png
   ```

## Example Output

### ASCII
```
+-- my-app@1.0.0
    +-- lib-a@2.3.1
    +-- lib-b@1.2.0
        +-- lib-c@0.9.0
```

### HTML
An interactive webpage with collapsible nodes, search functionality, and the ability to pin a dependency path for highlighting.

### DOT
A Graphviz-compatible `.dot` file that can be rendered into a visual graph, e.g., using `dot -Tpng`.

## Contributing

Contributions are welcome! Please open an issue or pull request for bug fixes, feature requests, or improvements. Some ideas:
- Add support for additional SBOM formats (e.g., SPDX Tag-Value).
- Enhance HTML output with more visualization options.
- Optimize for large SBOMs with thousands of components.

## Acknowledgments

- Inspired by the need for clear, accessible SBOM visualization tools.
- Built with simplicity and usability in mind for developers and security professionals.

Happy dependency tree exploring!
