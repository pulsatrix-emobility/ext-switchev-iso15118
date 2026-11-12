"""DEV-3994: SECC imports must not depend on optional environment loading."""

import subprocess
import sys

import pytest


@pytest.mark.parametrize(
    "module",
    [
        "iso15118.secc.secc_settings",
        "iso15118.secc.controller.interface",
        "iso15118.secc.controller.simulator",
    ],
)
def test_secc_module_imports_in_fresh_process(module):
    subprocess.run([sys.executable, "-c", f"import {module}"], check=True)
