from io import BytesIO
import pefile
from nxc.helpers.misc import CATEGORY


class NXCModule:
    """
    Module for detecting Windows lock screen backdoors
    Module by @E1A
    """

    name = "lockscreendoors"
    description = "Detect Windows lock screen backdoors by checking FileDescriptions of accessibility binaries."
    supported_protocols = ["smb"]
    category = CATEGORY.ENUMERATION

    def __init__(self):
        # List of exe names with expected descriptions
        self.expected_descriptions = {
            "utilman.exe": ["Utility Manager"],
            "narrator.exe": ["Screen Reader", "Narrator"],
            "sethc.exe": ["Accessibility shortcut keys"],
            "osk.exe": ["Accessibility On-Screen Keyboard"],
            "magnify.exe": ["Microsoft Screen Magnifier"],
            "EaseOfAccessDialog.exe": ["Ease of Access Dialog Host"],
            "voiceaccess.exe": ["Voice access"],  # Only on Windows 11 / Server 2025+
            "displayswitch.exe": ["Display Switch"],
            "atbroker.exe": ["Windows Assistive Technology Manager", "Transitions Accessible technologies between desktops"],
        }

        # If description matches one of these it's almost certainly backdoored
        self.backdoor_descriptions = [
            "Windows Command Processor",
            "Windows PowerShell"
        ]

    def options(self, context, module_options):
        """No options available"""

    def get_description(self, binary_data):
        # Extract the file description from version info
        try:
            pe = pefile.PE(data=binary_data, fast_load=True)
            pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_RESOURCE"]])
            for fileinfo in pe.FileInfo:
                for entry in fileinfo:
                    if entry.Key.decode() == "StringFileInfo":
                        for st in entry.StringTable:
                            desc = st.entries.get(b"FileDescription")
                            if desc:
                                return desc.decode().strip()
        except Exception as e:
            self.context.log.debug(f"Failed to extract PE info: {e}")
        return None

    def on_admin_login(self, context, connection):
        # get_description() logs through self.context, so give it the real logger from here.
        self.context = context
        target_path = "\\Windows\\System32"
        # Accessibility binaries are tiny (tens to hundreds of KB); anything this large is not one.
        max_size = 10 * 1024 * 1024
        tampered = False
        readable_file_found = False

        for exe, expected_descs in self.expected_descriptions.items():
            remote_path = f"{target_path}\\{exe}"
            try:
                # Bound the read: stat the remote file before pulling the whole thing into memory.
                try:
                    listing = connection.conn.listPath("C$", remote_path)
                except Exception as e:
                    context.log.debug(f"{exe}: not present or could not be listed: {e}")
                    continue

                file_size = listing[0].get_filesize() if listing else 0
                if file_size > max_size:
                    tampered = True
                    context.log.highlight(f"SUSPICIOUS: {exe} is {file_size} bytes, far larger than a legitimate accessibility binary (skipping parse)")
                    continue

                # Grab the binary from the share
                buf = BytesIO()
                connection.conn.getFile("C$", remote_path, buf.write)
                binary = buf.getvalue()

                # Extract the file description
                file_desc = self.get_description(binary)
                if file_desc is None:
                    # Could not parse the PE / find the description -> cannot vouch for this file.
                    tampered = True
                    context.log.fail(f"{exe}: could not parse FileDescription (treated as inconsistent)")
                    continue

                readable_file_found = True

                normalized = file_desc.strip()
                if not normalized:
                    # A blank or whitespace-only description is not a legitimate value.
                    tampered = True
                    context.log.highlight(f"SUSPICIOUS: {exe} has a blank or whitespace-only FileDescription")
                    continue

                # Check if the description is as expected
                if normalized not in expected_descs:
                    tampered = True
                    if normalized in self.backdoor_descriptions:
                        context.log.highlight(f"BACKDOOR DETECTED: {exe} has FileDescription '{normalized}'")
                    else:
                        if len(expected_descs) == 1:
                            expected_str = f"'{expected_descs[0]}'"
                        else:
                            expected_str = ", ".join(f"'{d}'" for d in expected_descs)
                            expected_str = f"one of: {expected_str}"
                        context.log.highlight(f"SUSPICIOUS: {exe} has unexpected FileDescription '{normalized}' (expected {expected_str})")
            except Exception as e:
                context.log.debug(f"Failed to process {exe}: {e}")

        if not readable_file_found:
            context.log.fail("Could not read any accessibility binary description; unable to determine lock screen backdoor status")
        elif not tampered:
            context.log.display("All lock screen executable descriptions are consistent with the expected values")
