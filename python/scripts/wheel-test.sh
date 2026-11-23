#!/bin/sh
# Builds the wheel, installs it into a fresh virtual environment outside the repository, runs the vectors
# and the integrity tests against the installed package (proves the spec data is inside the
# wheel), and checks that a wheel whose spec files were removed refuses to import.
#
#   scripts/wheel-test.sh [python-version]      default 3.11
set -eu

PYTHON_VERSION="${1:-3.11}"
HERE="$(cd "$(dirname "$0")/.." && pwd)"
WORK="$(cd "$(mktemp -d)" && pwd -P)"
trap 'rm -rf "$WORK"' EXIT

cd "$HERE"
uv build --wheel --out-dir "$WORK/dist"
# The wheel carries the license and the third-party notices (PEP 639): the files inside `.dist-info/licenses` and
# the metadata expression.
python3 - "$WORK"/dist/*.whl <<'PY'
import sys, zipfile
names = zipfile.ZipFile(sys.argv[1]).namelist()
metadata = zipfile.ZipFile(sys.argv[1]).read(
    next(name for name in names if name.endswith(".dist-info/METADATA"))
).decode()
assert any(name.endswith(".dist-info/licenses/LICENSE") for name in names), "the wheel holds no LICENSE"
assert any(name.endswith(".dist-info/licenses/NOTICE") for name in names), "the wheel holds no NOTICE"
assert "License-Expression: MIT" in metadata, "the wheel metadata has no MIT license expression"
PY
uv export --frozen --only-group dev --no-emit-project --format requirements-txt \
    -o "$WORK/dev-requirements.txt"
uv venv --python "$PYTHON_VERSION" "$WORK/venv"
VENV_PYTHON="$WORK/venv/bin/python"
uv pip install --python "$VENV_PYTHON" --require-hashes -r "$WORK/dev-requirements.txt"
uv pip install --python "$VENV_PYTHON" "$WORK"/dist/*.whl

cd "$WORK"
INSTALLED="$("$VENV_PYTHON" -c 'import droidrun_redaction; print(droidrun_redaction.__file__)')"
case "$INSTALLED" in
    "$WORK"/venv/*) ;;
    *) echo "the package was not imported from the wheel: $INSTALLED" >&2; exit 1 ;;
esac

"$VENV_PYTHON" -m pytest -q -p no:cacheprovider -c "$HERE/pyproject.toml" --rootdir "$HERE" \
    "$HERE/tests/test_vectors.py" "$HERE/tests/test_integrity.py"

PACKAGE_DIR="$(dirname "$INSTALLED")"
rm -r "$PACKAGE_DIR/spec"
if "$VENV_PYTHON" -c 'import droidrun_redaction' 2>"$WORK/import.err"; then
    echo "a wheel without its spec files imported" >&2
    exit 1
fi
grep -q 'SpecError: redaction spec data is missing' "$WORK/import.err"
echo "wheel test passed"
