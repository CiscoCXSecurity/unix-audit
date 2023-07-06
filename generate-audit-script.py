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

def load_commands(database_dir: str) -> Commands:
    commands = Commands()
    # check if directory exists
    if not os.path.isdir(database_dir):
        print(f"[E] Database directory not found: {database_dir}.  Run with no args for help.")
        sys.exit(1)

    print(f"[I] Loading commands from database directory: {database_dir}")

    # print number of .md files in directory
    num_files = len([filename for filename in os.listdir(database_dir) if filename.endswith(".md")])
    print(f"[I] Found {num_files} .md files in database directory.  Parsing...")

    for filename in os.listdir(database_dir):
        if filename.endswith(".md"):
            print(f"[I] Reading database file {filename}")
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

                        command = commands.add_or_get(current_title)
                        command.append(f"{line}\n")
                        command.tags = current_tags_list
                        command.platform_tags = current_platform_tags_list
                        continue

                    # Raise exception.  Should never get here
                    raise Exception(f"Unexpected state: {state}")

                print(f"[I] Parsed {len(commands.commands)} commands so far...")

    return commands

if __name__ == "__main__":

    available_commands = None

    if len(sys.argv) >= 2:
        database_dir = sys.argv[1]
        available_commands = load_commands(database_dir)

    if len(sys.argv) != 4:
        if available_commands is None:
            print("[E] No database directory specified.  Specify database directory of md files for a list of available platforms and tags.")
        else:
            print("[E] Missing arguments.  Specify database directory, platform tag, and other tags.")

        print("Usage: generate-audit-script.py <database-dir> <platform-tag> <other-tag,other-tag,...>\n\nUse 'all' for platform-tag to select all platforms (probably not useful!)\nUse 'all' for other-tag to select all tags\n\nExample: generate-audit-script.py path/dbdir linux any\n\n")

        if available_commands is not None:
            print(f"Available platforms: {', '.join(available_commands.get_platforms())}")
            print(f"Available tags: {', '.join(available_commands.get_tags())}")
        sys.exit(1)

    platform_tag = sys.argv[2]
    other_tags_string = sys.argv[3]
    checks = {}
    other_tags = other_tags_string.split(',')

    # check if each supplied platform_tag is valid in database or is a wildcard
    if not any([platform_tag in available_commands.get_platforms()]) or platform_tag in wildcards:
        print(f"[E] Invalid platform tag: {platform_tag}")
        print(f"Available platforms: {', '.join(available_commands.get_platforms())}")
        sys.exit(1)

    # check if each supplied other_tag is valid in database or is a wildcard
    if not (any([tag in available_commands.get_tags() for tag in other_tags]) or any([tag in wildcards for tag in other_tags])):
        print(f"[E] Invalid tag")
        print(f"Available tags: {', '.join(available_commands.get_tags())}")
        sys.exit(1)

    selected_commands = available_commands.find(platform_tag, other_tags)

    print(str(selected_commands))
    print("[*] Script:")
    print(selected_commands.get_script())
