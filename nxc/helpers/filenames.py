import ntpath
import os
import re

# Characters that are unsafe to embed in a filename or in a str.format template.
UNSAFE_CHARS = re.compile(r"[\x00-\x1f\x7f{}]")


def sanitize_path_component(value: str, max_len: int = 64) -> str:
    r"""Reduce an untrusted value to a safe single filename component.

    A server-controlled hostname or remote name can contain path separators,
    parent-directory references, drive anchors, or ``str.format`` braces. Such a
    value can escape the intended output directory or crash template rendering.

    This function keeps only the basename, removes both POSIX (``/``) and Windows
    (``\\``) separators, strips ``..`` sequences, ``{``/``}`` braces, and control
    characters, and truncates the result. An empty result becomes ``"unknown"``.
    """
    if value is None:
        return "unknown"

    # Take the basename for both separator styles so a mixed path cannot escape.
    value = ntpath.basename(os.path.basename(str(value)))

    # Remove parent-directory references and unsafe characters.
    value = value.replace("..", "")
    value = UNSAFE_CHARS.sub("", value)

    # Strip any residual separators and leading anchors.
    value = value.replace("/", "").replace("\\", "").strip(". ")

    if not value:
        return "unknown"

    return value[:max_len]
