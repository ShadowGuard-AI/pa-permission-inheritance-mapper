# pa-permission-inheritance-mapper
Maps permission inheritance chains and identifies potential vulnerabilities due to unintended permission propagation. - Focused on Tools for analyzing and assessing file system permissions

## Install
`git clone https://github.com/ShadowStrikeHQ/pa-permission-inheritance-mapper`

## Usage
`./pa-permission-inheritance-mapper [params]`

## Parameters
- `-h`: Show help message and exit
- `-v`: No description provided
- `-i`: Ignore files and directories matching this glob style pattern. Patterns are read with the documented pathspec `from_lines` constructor using git wildmatch patterns.
- `-o`: Output the results to a file. The output path must be outside the scanned tree; an output path inside the scanned tree is refused with exit 1.

## Behaviour notes
- A child entry is flagged as vulnerable when it grants a read, write, or execute bit to a class (owner, group, or other) that its parent does not grant to that class or to any wider class (other is wider than group, group is wider than owner). The comparison is on permission bits, not on the numeric mode value: a child at 0o077 under a parent at 0o400 is flagged, because the parent grants write and execute to nobody, and a child at 0o400 under a parent at 0o077 is not flagged, because it grants only owner read, a kind the parent already grants to the wider group and other classes.
- A root path that is a plain file, and an empty directory, contain no inheritance relationships. Both report that nothing was scanned and exit non-zero instead of printing an empty result as a finished run.
- If writing the output file fails, the run exits non-zero.

## License
Copyright (c) ShadowStrikeHQ
