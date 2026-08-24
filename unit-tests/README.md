# Unit tests

For the Ledger unit testing framework introduction, see `ledger-secure-sdk/cmake/LedgerUT.cmake`,
documented in `ledger-secure-sdk/cmake/USAGE.md`.

This directory is included from the app's root `CMakeLists.txt` (via `add_subdirectory(unit-tests)`),
which owns the SDK subdirectory, `LedgerUT` and the shared `app` coverage library — it is no longer a
standalone CMake project and cannot be configured directly from within `unit-tests/`.

Requires the `mbr/cmake2` branch of `ledger-secure-sdk` (full CMake device-build + unit-test support),
not the `API_LEVEL_26` branch used before this app migrated to 100%-CMake.

Build and run from the repo root, using the `unit-tests` preset:

```bash
BOLOS_SDK=/path/to/ledger-secure-sdk cmake --preset unit-tests
BOLOS_SDK=/path/to/ledger-secure-sdk cmake --build --preset unit-tests
ctest --preset unit-tests --output-on-failure
```

Or without presets:

```bash
BOLOS_SDK=/path/to/ledger-secure-sdk cmake -B build/unit-tests -DBUILD_UNIT_TESTS=ON \
    -DCMAKE_TOOLCHAIN_FILE=$BOLOS_SDK/cmake/toolchains/toolchain_gcc_x86.cmake
cmake --build build/unit-tests
ctest --test-dir build/unit-tests --output-on-failure
```
