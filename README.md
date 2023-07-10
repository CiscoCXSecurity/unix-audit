# unix-audit
Framework for generating audit commands for Unix security audits

# Usage
```
Usage: generate-audit-script.py <check-database-dir> <platform-tag> <other-tag,other-tag,...>

Use 'all' for other-tag to select all tags

Example: generate-audit-script.py path/dbdir linux all

Available platforms: aix, linux, solaris
Available tags: network-stack-tuning, logging, privilege-escalation, file-permissions, exploit-mitigation, authentication, resource-limits, access-control, common-services, networking, cryptography, environment, software-installed, informational, important-file-locations
```

# Examples
```
python3 generate-audit-script.py ./checks-database/ linux all > linux-audit.sh
python3 generate-audit-script.py ./checks-database/ solaris all > solaris-audit.sh
python3 generate-audit-script.py ./checks-database/ aix all > aix-audit.sh
python3 generate-audit-script.py ./checks-database/ linux exploit-mitigation,software-installed > smaller-audit.sh
```
