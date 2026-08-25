import re
from pathlib import Path

from ragger.backend.interface import BackendInterface

from application_client.tron_command_sender import TronCommandSender
from application_client.tron_response_unpacker import unpack_get_version_response


def test_version(backend: BackendInterface) -> None:
    client = TronCommandSender(backend)
    major, minor, patch = unpack_get_version_response(client.get_version().data)

    version_file = (Path(__file__).parent.parent / "VERSION").read_text(encoding="utf-8")
    ref_major, ref_minor, ref_patch = re.findall(r"(\d+)\.(\d+)\.(\d+)", version_file)[0]
    assert (major, minor, patch) == (int(ref_major), int(ref_minor), int(ref_patch))
