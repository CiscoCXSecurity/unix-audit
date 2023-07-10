# Generate Mode

This directory contains example files for the "generate" mode of unix-audit.

The purpose of "generate" mode is to create an audit scripts using a subset of the checks database.

Example command lines to generate audit scripts:

```
python3 unix-audit.py generate ./checks-database/ aix all > audit-scripts/aix-audit.sh
python3 unix-audit.py generate ./checks-database/ linux all > audit-scripts/linux-audit.sh
python3 unix-audit.py generate ./checks-database/ solaris all > audit-scripts/solaris-audit.sh
```

Consider scripts in this directory to be samples only. They are not guaranteed to reflect the latest checks database.
