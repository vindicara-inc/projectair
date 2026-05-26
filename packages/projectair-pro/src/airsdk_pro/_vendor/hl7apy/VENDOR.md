# Vendored: hl7apy

## Source

- **Package:** hl7apy
- **Version:** 1.3.5
- **PyPI URL:** https://pypi.org/project/hl7apy/1.3.5/
- **Wheel filename:** hl7apy-1.3.5-py2.py3-none-any.whl
- **SHA-256 (wheel):** c8b80ff5ad020bf9c1e68a6395cf45cb78db621f65569d1798c46eb1b657e27b
- **Upstream repository:** https://github.com/crs4/hl7apy
- **License:** MIT License
- **Date vendored:** 2026-05-25

## Why vendored

hl7apy is an HL7v2 parser with significant long-tail complexity (escape sequences, Z-segments, variable-precision timestamps, vendor quirks). We own the typed Pydantic wrapper on top; hl7apy handles the parsing internals. Vendoring pins the exact version and removes the runtime dependency conflict surface.

## Import rewriting

All internal imports of the form `from hl7apy` and `from hl7apy.xxx` were rewritten to `from airsdk_pro._vendor.hl7apy` and `from airsdk_pro._vendor.hl7apy.xxx` respectively. The `_discover_libraries()` function in `__init__.py` was also updated to emit `airsdk_pro._vendor.hl7apy.v2_x` module paths so `importlib.import_module` resolves correctly.

## Re-vendoring instructions

To re-vendor a newer version:

```bash
# 1. Download the wheel
pip download hl7apy==<VERSION> -d /tmp/hl7apy_dl --no-deps
shasum -a 256 /tmp/hl7apy_dl/hl7apy-<VERSION>*.whl

# 2. Install to a temp location and copy
pip install hl7apy==<VERSION> --target /tmp/hl7apy_check --no-deps
cp -r /tmp/hl7apy_check/hl7apy packages/projectair-pro/src/airsdk_pro/_vendor/hl7apy

# 3. Remove __pycache__
find packages/projectair-pro/src/airsdk_pro/_vendor/hl7apy -name "__pycache__" -type d -exec rm -rf {} +

# 4. Rewrite absolute imports
find packages/projectair-pro/src/airsdk_pro/_vendor/hl7apy -name "*.py" \
  -exec sed -i '' 's/from hl7apy\./from airsdk_pro._vendor.hl7apy./g' {} + \
  -exec sed -i '' 's/from hl7apy import/from airsdk_pro._vendor.hl7apy import/g' {} +

# 5. Fix _discover_libraries() in __init__.py:
#    Change "hl7apy.{}".format(o) to "airsdk_pro._vendor.hl7apy.{}".format(o)

# 6. Update SHA-256 and version in this file
```

## License

The MIT License applies to all files in this directory (see hl7apy upstream repository for the full text).
