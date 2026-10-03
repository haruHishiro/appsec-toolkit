"""Tests for the version module and its single-source-of-truth contract."""

import importlib.util
import re
from pathlib import Path


PKG_DIR = Path(__file__).resolve().parent.parent
VERSION_FILE = PKG_DIR / "_version.py"


def test_version_importable_directly():
    from sqli_toolkit._version import __version__
    assert isinstance(__version__, str)
    assert __version__


def test_version_exposed_in_package():
    import sqli_toolkit
    from sqli_toolkit._version import __version__
    assert sqli_toolkit.__version__ == __version__


def test_version_in_all():
    import sqli_toolkit
    assert "__version__" in sqli_toolkit.__all__


def test_version_is_semver_like():
    from sqli_toolkit._version import __version__
    assert re.match(r"^\d+\.\d+\.\d+", __version__), (
        f"version {__version__!r} does not look like semver"
    )


def test_version_file_exists():
    assert VERSION_FILE.exists(), f"{VERSION_FILE} not found"


def test_version_file_has_no_builder_imports():
    """The file that holds the version must not import the heavy modules."""
    text = VERSION_FILE.read_text(encoding="utf-8")
    forbidden = ["union_builder", "pack_builder", "helper"]
    for name in forbidden:
        assert name not in text, (
            f"_version.py must not reference {name}"
        )


def test_version_loadable_without_package_import():
    """Load _version.py directly by file path; the rest of the package
    must not appear in sys.modules as a result."""
    import sys

    # make sure the package is not already cached from earlier tests
    for mod in list(sys.modules):
        if mod.startswith("sqli_toolkit"):
            del sys.modules[mod]

    spec = importlib.util.spec_from_file_location(
        "sqli_toolkit_version_probe", VERSION_FILE
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    assert hasattr(module, "__version__")
    assert isinstance(module.__version__, str)

    # loading by path must not trigger the package __init__
    assert "sqli_toolkit" not in sys.modules
    assert "sqli_toolkit.union_builder" not in sys.modules
    assert "sqli_toolkit.pack_builder" not in sys.modules


def test_version_defined_only_in_version_file():
    """__version__ must not be redefined in other package files."""
    offenders = []
    for py in PKG_DIR.rglob("*.py"):
        if py.name == "_version.py":
            continue
        text = py.read_text(encoding="utf-8")
        for line in text.splitlines():
            stripped = line.strip()
            if stripped.startswith("__version__") and "=" in stripped:
                if "import" not in stripped:
                    offenders.append(str(py))
                    break
    assert not offenders, f"__version__ reassigned in: {offenders}"
