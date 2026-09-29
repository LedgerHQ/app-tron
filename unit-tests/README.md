# Unit tests

For the Ledger unit testing framework introduction, see `ledger-secure-sdk/cmake/LedgerUT.cmake`,
documented in `ledger-secure-sdk/cmake/USAGE.md`.

Build against the `API_LEVEL_26` branch of `ledger-secure-sdk` (the branch with the stable,
UT-only CMake support — not a WIP full-CMake-migration branch):

```bash
BOLOS_SDK=/path/to/ledger-secure-sdk cmake -Bbuild -H.
BOLOS_SDK=/path/to/ledger-secure-sdk cmake --build build
ctest --test-dir build --output-on-failure
```
