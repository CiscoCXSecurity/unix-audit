# unix-audit
Framework for generating audit commands for Unix security audits.

unix-audit allows you to maintain a list of commands in markdown (.md) format, then generate scripts from those markdown pages.  You can [view the markdown database files here](/unix-audit/checks-database/).  Feel free to maintain your own database of checks or to contribute back to this public repository (also see [contributing](CONTRIBUTING.md))

You can optionally tag your commands (or whole sections of commands) to enable generation of scripts that contain only a subset of commands from your checks database.  This can be useful if you need to perform different types of audit (e.g. you might have a normal security audit, a bug-hunting audit, a privilege escalation check, checks for detective controls, checks for exposed secrets, commands that help you collect data for graphing, a quick audit, a slow audit, audits that generate extra files, audits that don't generate extra files, etc.)

The markdown database format allows the use of comments - in fact only code blocks and titles are used during script generation, everything else is ignored.  This can help to document your commands for users.

The markdown format (parsed or unparsed) can also make it easier to identify gaps in your scripts - e.g. maybe your Solaris audits don't include commands for all the checks performed on Linux.  This can be quite more difficult for you only maintain source code.

# Quick Start
unix-audit can generate shell scripts containing the commands you want to run on the target system:
```
python3 generate-audit-script.py ./checks-database/ linux all > linux-audit.sh
python3 generate-audit-script.py ./checks-database/ solaris all > solaris-audit.sh
python3 generate-audit-script.py ./checks-database/ aix all > aix-audit.sh
python3 generate-audit-script.py ./checks-database/ linux exploit-mitigation,software-installed > smaller-audit.sh
```
You can get a list of supported platforms and available tags by specifying only your database directory:
```
$ python3 generate-audit-script.py ./checks-database/
...
Available platforms: aix, linux, solaris
Available tags: network-stack-tuning, logging, privilege-escalation, file-permissions, exploit-mitigation, authentication, resource-limits, access-control, common-services, networking, cryptography, environment, software-installed, informational, important-file-locations
```
Upload the script to the target system (e.g. scp or copy-paste), run it and collect the output, e.g.
```
# sh audit.sh > audit-output.sh
```
Then copy the output file back to your own systems for analysis.

The public version of unix-audit doesn't analyze data, it just collects it.  This may change in future.

# Usage
```
Usage: generate-audit-script.py <check-database-dir> <platform-tag> <other-tag,other-tag,...>

Use 'all' for other-tag to select all tags

Example: generate-audit-script.py path/dbdir linux all

Available platforms: aix, linux, solaris
Available tags: network-stack-tuning, logging, privilege-escalation, file-permissions, exploit-mitigation, authentication, resource-limits, access-control, common-services, networking, cryptography, environment, software-installed, informational, important-file-locations
```
# What is unix-audit used for?

unix-audit is mostly used by Cisco's offensive security testing teams (penetration testers and red teamers) to collect information from systems they are asked to audit.  The collected data is parsed and analysed offline and ultimately used to generate details of security weakenesses and corresponding recommendations for customers.  The depth of such audits can be fairly extensive for Build Review type activities.  Conversely, it can be fairly light for ad-hoc checks for compromised systems during penetration tests.

Analysis tools for parsing have not been released publicly at the time of writing.

There are lots of other use-cases and potential use-cases too, e.g.
* Supported password strength audits (collecting shadow files or similar)
* Supporting the graphing of SSH trust relationships
* Bug hunting for a particular class of security vulnerability
* Searching for exposed secrets in home directories

If you have commands that your team needs to run on customer systems, it should be easy to adapt for your use-case too.

Also check out [unix_collector](https://github.com/CiscoCXSecurity/unix_collector) which is maintained by Cisco's teams that focus on detection and response.

# How to update commands / scripts

To update the [checks-database](checks-database/), just go ahead and edit the markdown files - using the github editor or your preferred markdown editor.

After updating the checks database, any existing scripts will be out of date and you'll need to regenerate them.

To "compile", use the generate-audit-script.py file as directed above.

# Tips on running audit scripts

Remember the following when running audit scripts:
* Collect the output from your script by redirecting output, using "script", "tee" or somethign similar.
* Commands in the checks database generally don't create files, but some do.  So run in a clean directory so you can easily identify any other created files that you may want to retrieve at the end of the audit.
* Don't fill up the disk partition.  You script might run for a long time and generate a lot of output.  Check there's plenty of disk space before you start.
* Be considerate about degrading system performance.  Some commands can use a lot of CPU or disk I/O.  In practice we haven't noticed problems.  But if you were to audit 100 systems simultaneously and they all shared a resource (hypervisor/SAN), you may run into problems.

# How to check for gaps in your scripts

If one of the platforms you audit (e.g. AIX) had less checks than another platform (e.g. Linux), how would you know?  unix-audit seeks to address this in two ways:
* Encourage the writing of markdown files in a common format (and each team can choose a format that works for them). This support manual side-by-side comparison of docs for two different platforms.
* Using a markdown parser to compare checks for two different platforms.

Use `find-audit-gaps.py` to identify checks (markdown titles) that appear for one platform but no another:
```
find-audit-gaps.py ./checks-database/ linux solaris
```
