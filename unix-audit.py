import sys
import os
import re

wildcards = ["*", "any", "all"]

class Command:
    def __init__(self, title: str):
        self.title = title
        self.tags = []
        self.platform_tags = []
        self.code_block = ""

    def append(self, line: str):
        self.code_block = self.code_block + line

    def __str__(self):
        return f"Title: {self.title}\nTags: {self.tags}\nPlatformTags: {self.platform_tags}\nCode: {self.code_block}"

class Commands:
    def __init__(self):
        self.commands = [] # list of Command objects

    def add_or_get(self, title: str):
        for command in self.commands:
            if command.title == title:
                return command

        command = Command(title)
        self.commands.append(command)
        return command

    def get_platforms(self):
        platforms = set()
        for command in self.commands:
            for platform in command.platform_tags:
                platforms.add(platform)
        return platforms

    def find_title(self, title: str):
        for command in self.commands:
            if command.title == title:
                return command
        return None

    def find(self, platform: str, tags: list): # Lists of strings
        found_commands_list = []

        for command in self.commands:
            applicable_platform = False
            if command.platform_tags:
                # check if platform is a wildcard
                if platform in wildcards:
                    applicable_platform = True

                # check if platform matches platform for command
                elif platform in command.platform_tags:
                    applicable_platform = True
            if applicable_platform:
                applicable_tag = False
                if command.tags:
                    # check if tag is a wildcard
                    if any([tag in wildcards for tag in tags]):
                        applicable_tag = True

                    # check if tag matches tag for command
                    elif any([tag in command.tags for tag in tags]):
                        applicable_tag = True

                if applicable_tag:
                    found_commands_list.append(command)

        found_commands = Commands()
        found_commands.commands = found_commands_list
        return found_commands

    def get_tags(self):
        tags = set()
        for command in self.commands:
            for tag in command.tags:
                tags.add(tag)
        return tags

    def __str__(self):
        return "\n".join([str(command) for command in self.commands])

    def __iter__(self):
        return iter(self.commands)

    def get_script(self):
        script = ""
        for command in self.commands:
            script = script + f"echo \"=== {command.title}\"===\n"
            script = script + command.code_block + "\n"
        return script

    def count(self):
        return len(self.commands)

    def load_from_directory(self, database_dir: str):
        # check if directory exists
        if not os.path.isdir(database_dir):
            print(f"[E] Database directory not found: {database_dir}.  Run with no args for help.")
            sys.exit(1)

        #print(f"[I] Loading commands from database directory: {database_dir}")

        # print number of .md files in directory
        num_files = len([filename for filename in os.listdir(database_dir) if filename.endswith(".md")])
        #print(f"[I] Found {num_files} .md files in database directory.  Parsing...")

        for filename in os.listdir(database_dir):
            if filename.endswith(".md"):
                #print(f"[I] Reading database file {filename}")
                with open(os.path.join(database_dir, filename), 'r') as infile:
                    current_tags_dict = {}
                    current_platform_tags_dict = {}
                    section_title = {}
                    level = None
                    state = "outside_code_section"
                    for line in infile.readlines():
                        line = line.rstrip()

                        m = re.match(r'^(#+)\s*(.*?)\s*$', line)
                        if state == "outside_code_section" and m:  # need to be careful to ignore shell commends in code blocks
                            level = len(m.group(1))
                            section_title[level] = m.group(2)
                            state = "outside_code_section"
                            continue

                        # check if line is like: PlatformTags: linux
                        m = re.match(r'^\s*PlatformTag:\s*(.*?)\s*$', line)
                        if m:
                            platform_tags_string = m.group(1)
                            current_platform_tags_dict[level] = [tag.strip() for tag in platform_tags_string.split(',')]
                            continue

                        # Tags: line
                        m = re.match(r'^\s*Tags:\s*(.*?)\s*$', line)
                        if m:
                            tags_string = m.group(1)
                            current_tags_dict[level] = [tag.strip() for tag in tags_string.split(',')]
                            continue

                        # code block boundary
                        m = re.match(r'^\s*```\s*$', line)
                        if m:
                            if state == "outside_code_section":
                                state = "in_code_section"
                                continue

                            if state == "in_code_section":
                                state = "outside_code_section"
                                continue

                        if state == "outside_code_section":
                            #print(f"[D] Ignoring: {line}")
                            continue

                        if state == "in_code_section":
                            # Save command from code block
                            current_title = None
                            current_tags_list = []
                            current_platform_tags_list = []

                            for l in range(1, level+1):
                                if l in current_tags_dict:
                                    current_tags_list = current_tags_list + current_tags_dict[l]

                                if l in current_platform_tags_dict:
                                    current_platform_tags_list = current_platform_tags_list + current_platform_tags_dict[l]

                                if current_title is None:
                                    current_title = section_title[l]
                                else:
                                    current_title = current_title + " > " + section_title[l]

                            command = self.add_or_get(current_title)
                            command.append(f"{line}\n")
                            command.tags = current_tags_list
                            command.platform_tags = current_platform_tags_list
                            continue

                        # Raise exception.  Should never get here
                        raise Exception(f"Unexpected state: {state}")

                    #print(f"[I] Parsed {len(self.commands)} commands so far...")

    def get_titles(self):
        titles = set()
        for command in self.commands:
            titles.add(command.title)
        return set(sorted(titles))


def usage():
    print("Usage: unix-audit.py mode args")
    print("")
    print("Modes:")
    print(" python3 unix-audit.py list <database-dir>")
    print(" python3 unix-audit.py generate <database-dir> <platform-tag> <other-tag,other-tag,...>")
    print(" python3 unix-audit.py compare <database-dir> <platform-tag1> <platform-tag2> <other-tag,other-tag,...>")
    print("")
    print("List mode - lists the platforms and tags available for other modes.  Examples:")
    print("")
    print(" python3 unix-audit.py list ./checks-database/")
    print("")
    print("Generate mode - used to generate an audit script from md files.  Examples:")
    print("")
    print(" python3 unix-audit.py generate ./checks-database/ linux all > audit-scripts/linux-audit.sh")
    print(" python3 unix-audit.py generate ./checks-database/ aix all > audit-scripts/aix-audit.sh")
    print(" python3 unix-audit.py generate ./checks-database/ solaris all > audit-scripts/solaris-audit.sh")
    print("")
    print("Compare mode - find differences in commands for 2 or more platforms.  Examples:")
    print("")
    print(" python unix-audit.py compare ./checks-database/ all all > compare/comparison.md")
    print(" python3 unix-audit.py compare ./checks-database/ linux,solaris > linux-solaris-compare.md")
    print(" python3 unix-audit.py compare ./checks-database/ all authentication,logging > linux-solaris-compare.md")
    print("")


if __name__ == "__main__":
    # parse mode as first command line arg
    if len(sys.argv) < 2:
        print("[E] Missing mode.  Specify 'generate', 'list', or 'compare' as first argument.")
        usage()
        sys.exit(1)

    mode = sys.argv[1]

    if mode not in ["generate", "list", "compare"]:
        print("[E] Invalid mode.  Specify 'generate', 'list', or 'compare' as first argument.")
        usage()
        sys.exit(1)

    # parse database directory as second command line arg
    if len(sys.argv) < 3:
        print("[E] Missing database directory.  Specify database directory as second argument.")
        usage()
        sys.exit(1)

    database_dir = sys.argv[2]
    available_commands = Commands()
    available_commands.load_from_directory(database_dir)

    if available_commands.count() == 0:
        print(f"[E] No commands found in database directory: {database_dir}.  Check md files are present and formatted correctly.")
        usage()
        sys.exit(1)

    if mode == "list":
        print(f"Available platforms: {', '.join(available_commands.get_platforms())}")
        print(f"Available tags: {', '.join(available_commands.get_tags())}")
        sys.exit(0)

    # "generate" and "compare" modes take same arguments

    # parse platform tag as third command line arg
    if len(sys.argv) < 4:
        print("[E] Missing platform tag.  Specify platform tag as third argument.")
        usage()
        sys.exit(1)

    platform_tags_string = sys.argv[3]
    platform_tags = platform_tags_string.split(',')

    # check if each supplied platform_tag is valid in database or is a wildcard
    for platform_tag in platform_tags:
        if platform_tag not in available_commands.get_platforms() and platform_tag not in wildcards:
            print(f"[E] Invalid platform tag: {platform_tag}")
            print(f"Available platforms: {', '.join(available_commands.get_platforms())}")
            sys.exit(1)

    # parse other tags as fourth command line arg
    if len(sys.argv) < 5:
        print("[E] Missing other tags.  Specify other tags as fourth argument.")
        usage()
        sys.exit(1)

    other_tags = sys.argv[4].split(',')

    # check if each supplied other_tag is valid in database or is a wildcard
    for tag in other_tags:
        if tag not in available_commands.get_tags() and tag not in wildcards:
            print(f"[E] Invalid tag: {tag}")
            print(f"Available tags: {', '.join(available_commands.get_tags())}")
            usage()
            sys.exit(1)

    if mode == "generate":
        selected_commands = available_commands.find(platform_tags_string, other_tags)
        # print(str(selected_commands))
        print(selected_commands.get_script())
        sys.exit(0)

    if mode == "compare":
        selected_commands = {}
        titles = {}

        if platform_tags_string in wildcards:
            platform_tags = sorted(list(available_commands.get_platforms()))

        platform_count = len(platform_tags)

        for platform_tag in platform_tags:
            selected_commands[platform_tag] = available_commands.find(platform_tag, other_tags)
            titles[platform_tag] = selected_commands[platform_tag].get_titles()

            # strip off first field delimited with >.  This is the platform name.
            titles[platform_tag] = set([">".join(title.split(">")[1:]).lstrip() for title in titles[platform_tag]])

        union = set()

        for platform_tag in platform_tags:
            union = union.union(titles[platform_tag])

        header_row = ["Check Title"] + platform_tags
        print(f"| {' | '.join(header_row)} |")
        print(f"| {' | '.join(['---' for i in range(platform_count + 1)])} |")

        for title in sorted(union):
            row = []
            row.append(title)

            for platform_tag in platform_tags:
                if title in titles[platform_tag]:
                    row.append("Yes")
                else:
                    row.append("No")

            print(f"| {' | '.join(row)} |")

        sys.exit(0)






