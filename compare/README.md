# Compare Mode

This directory contains example files for the "compare" mode of unix-audit.

The purpose of "compare" mode is to highlight when audit commands are missing for a particular platform.

An example command line to generate a compare report is:

```
python unix-audit.py compare ./checks-database/ all all > compare/comparison.md
```

Consider reports in this directory to be samples only. They are not guaranteed to reflect the latest checks database.
