import argparse
import logging
import os
import stat
import sys
from typing import Dict, List, Tuple

# Optional dependencies (install with pip install pathspec rich)
try:
    import pathspec
    from rich.console import Console
    from rich.table import Column, Table
except ImportError:
    pathspec = None
    Console = None
    Table = None


# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def setup_argparse():
    """
    Sets up the argument parser for the command-line interface.

    Returns:
        argparse.ArgumentParser: The configured argument parser.
    """
    parser = argparse.ArgumentParser(
        description="Maps permission inheritance chains and identifies potential vulnerabilities.",
        epilog="Example usage: python pa_permission_inheritance_mapper.py /path/to/scan"
    )
    parser.add_argument(
        "path",
        nargs="?",
        default=".",
        help="The path to scan for permission inheritance (default: current directory)"
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose output (debug logging)"
    )
    parser.add_argument(
        "-i", "--ignore",
        metavar="PATTERN",
        action="append",
        default=[],
        help="Ignore files/directories matching this pattern (glob-style)"
    )
    parser.add_argument(
        "-o", "--output",
        metavar="FILE",
        help="Output the results to a file (default: stdout)"
    )

    return parser


def get_permissions(path: str) -> Dict[str, int]:
    """
    Retrieves permissions for a given file or directory.

    Args:
        path (str): The path to the file or directory.

    Returns:
        Dict[str, int]: A dictionary containing the permissions in octal format.

    Raises:
        OSError: If the path does not exist or is inaccessible.
    """
    try:
        mode = os.stat(path).st_mode
        permissions = {
            "octal": stat.S_IMODE(mode)  # Get permission bits
        }
        return permissions
    except OSError as e:
        logging.error(f"Error getting permissions for {path}: {e}")
        raise


def build_inheritance_graph(root_path: str, ignore_patterns: List[str] = []) -> Dict[str, List[str]]:
    """
    Builds a graph representing the permission inheritance relationships.

    Args:
        root_path (str): The root path to start the traversal from.
        ignore_patterns (List[str]): A list of glob-style patterns to ignore.

    Returns:
        Dict[str, List[str]]: A dictionary representing the inheritance graph.
                             Keys are paths, and values are lists of child paths.
    """
    graph: Dict[str, List[str]] = {}
    spec = None
    if ignore_patterns:
        if pathspec is None:
            raise RuntimeError("Ignore patterns were given but the pathspec package is not installed.")
        # from_lines with the git wildmatch pattern class is the
        # documented PathSpec constructor surface.
        spec = pathspec.PathSpec.from_lines("gitwildmatch", ignore_patterns)

    for root, dirs, files in os.walk(root_path):
        if spec and spec.match_file(root):
            dirs[:] = [] # Modify dirs in-place to prevent recursion
            continue

        # An ignored directory is still listed as a child of its parent by
        # the parent loop, it just gets no entry of its own when the walk
        # reaches it. find_vulnerable_paths then stats it as a child like
        # any other, so ignoring a path hides its subtree, not itself.
        graph[root] = []
        for name in dirs + files:
            full_path = os.path.join(root, name)
            if spec and spec.match_file(full_path):
                continue
            graph[root].append(full_path)

    return graph

def find_vulnerable_paths(graph: Dict[str, List[str]]) -> List[Tuple[str, str]]:
    """
    Identifies paths with potentially vulnerable permission inheritance.

    A child is flagged when it grants a read, write, or execute bit to a
    class (owner, group, or other) that its parent does not grant to
    that class or to any wider class (other is wider than group, and
    group is wider than owner). The comparison is on permission bits,
    not on numeric mode values: numeric order weights owner bits above
    group and other bits, so a child at 0o077 under a parent at 0o400
    scores lower numerically while granting kinds of access the parent
    grants to nobody, and a child at 0o400 under a parent at 0o077
    scores higher numerically while granting only owner read, a kind
    the parent already grants to the wider group and other classes.

    Args:
        graph (Dict[str, List[str]]): The permission inheritance graph.

    Returns:
        List[Tuple[str, str]]: A list of tuples, where each tuple contains the vulnerable path
                              and a description of the vulnerability.
    """
    vulnerable_paths: List[Tuple[str, str]] = []

    for parent, children in graph.items():
        try:
            parent_permissions = get_permissions(parent)
        except OSError:
            continue

        for child in children:
            try:
                child_permissions = get_permissions(child)
            except OSError:
                continue
            child_mode = child_permissions["octal"]
            parent_mode = parent_permissions["octal"]
            # Per class, the parent coverage is the bits the parent grants
            # to that class or to any wider class: owner is covered by
            # owner, group, and other; group by group and other; other
            # only by other.
            extra = 0
            # Masking each class to three bits drops the special bits entirely.
            # A child that adds setuid over its parent is invisible to this test,
            # because S_IMODE carried the bit in and the shift and mask throw
            # it away.
            for shift in (6, 3, 0):
                child_class = (child_mode >> shift) & 0o7
                parent_coverage = 0
                for cov_shift in range(shift, -1, -3):
                    parent_coverage |= (parent_mode >> cov_shift) & 0o7
                extra |= (child_class & ~parent_coverage) << shift
            if extra:
                vulnerable_paths.append((child, f"Child grants permission bits its parent does not grant to that class or any wider class ({oct(child_mode)} vs parent {oct(parent_mode)}; extra bits {oct(extra)})"))

    return vulnerable_paths


def output_results(vulnerable_paths: List[Tuple[str, str]], output_file: str = None, use_rich: bool = True):
    """
    Outputs the results to the console or a file.

    Args:
        vulnerable_paths (List[Tuple[str, str]]): A list of tuples containing vulnerable paths and descriptions.
        output_file (str, optional): The file to output the results to. Defaults to None (stdout).
        use_rich (bool, optional): Whether to use rich formatting for output. Defaults to True if rich is installed.
    """

    # The output file is opened before the try, so an unwritable path
    # raises out of this function into main instead of hitting the error
    # logging inside it. The finally below closes only real files; I
    # never close stdout.
    output_stream = sys.stdout if output_file is None else open(output_file, "w")

    try:
        if use_rich and Console and Table:
            console = Console(file=output_stream)
            table = Table(title="Vulnerable Paths", show_header=True, header_style="bold magenta")
            table.add_column("Path", style="cyan")
            table.add_column("Vulnerability", style="red")

            for path, vulnerability in vulnerable_paths:
                table.add_row(path, vulnerability)

            console.print(table)
        else:
            for path, vulnerability in vulnerable_paths:
                print(f"Path: {path}\nVulnerability: {vulnerability}\n", file=output_stream)

    except Exception as e:
        logging.error(f"Error outputting results: {e}")
        raise
    finally:
        if output_file is not None:
            output_stream.close()


def main():
    """
    Main function to execute the permission inheritance mapper.
    """
    parser = setup_argparse()
    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
        logging.debug("Verbose mode enabled.")

    root_path = args.path
    ignore_patterns = args.ignore
    output_file = args.output

    # Validate input path
    if not os.path.exists(root_path):
        logging.error(f"Path '{root_path}' does not exist.")
        sys.exit(1)

    # The output file may not overwrite a file inside the scanned tree.
    if output_file:
        resolved_root = os.path.realpath(root_path)
        resolved_output = os.path.realpath(output_file)
        if resolved_output == resolved_root or resolved_output.startswith(resolved_root + os.sep):
            logging.error(f"Output path '{output_file}' is inside the scanned tree '{root_path}'; refusing to overwrite a scanned file.")
            sys.exit(1)

    try:
        logging.info(f"Building inheritance graph for {root_path}...")
        # os.walk does not follow directory symlinks, so a tree reached only
        # through a link is not in the graph at all. Nothing in the output
        # records that the link was skipped.
        graph = build_inheritance_graph(root_path, ignore_patterns)

        # A plain file root and an empty directory hold no inheritance
        # relationship at all, so there is nothing to report as scanned.
        if not any(graph.values()):
            logging.error(f"No entries were found under '{root_path}'; nothing was scanned.")
            sys.exit(1)

        logging.info("Finding vulnerable paths...")
        vulnerable_paths = find_vulnerable_paths(graph)

        logging.info("Outputting results...")
        output_results(vulnerable_paths, output_file)

        logging.info("Finished.")

    except Exception as e:
        logging.error(f"An unexpected error occurred: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()