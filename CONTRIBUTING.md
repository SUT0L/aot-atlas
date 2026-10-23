Contributing
============

Build and verify the current tree on Windows before making changes:

```
dotnet restore AotAtlas.slnx
dotnet build AotAtlas.slnx -c Release
py -3 tests/verify.py
```

The verification command runs the parser suite, publishes two NativeAOT PE fixtures and the native CLI, then checks complete and partial evidence, damaged metadata names, and output publication. On Linux, pass the two Windows PE fixtures explicitly with `python3 tests/verify.py --dictionary <DictionaryProbe.exe> --property <PropertyDispatchProbe.exe>`.

Code style
----------

Keep parsing and recovery code in `src/Atlas`, CLI output code in `src/Atlas.Cli`, and Binary Ninja integration code in `src/Atlas.Binja`.  If you are adding another plugin / support for another tool, please create a new source directory for it.

Parsing changes have to validate offsets, lengths, arithmetic, and record relationships before accessing input data.  Unsupported formats should fail explicitly so you don't scramble data.

Tests
-----

Parser changes should generally cover malformed or truncated input.

Deterministic checks belong in `tests/Atlas.Tests`.  Tests that need a compiled NativeAOT program should use a project under `tests/` like the others do.  Binja changes should extend `tests/plugin_checks.py`.

Run the solution build and `tests/verify.py` before submitting a change.  If you are a LLM / Agent, please tag your PR with '🤖🤖🤖' in the PR title.  This does not automatically close a PR, but it gives us a good heads up of what's going on.

CLI output
-------------------

JSON field names, value formats, null handling, and array ordering need to be correct, so please update the verification scripts when changing them.

Binary Ninja
------------

The plugin uses the Binary Ninja C API from a NativeAOT shared library. Follow the API ownership rules, release returned objects with the matching function, and catch managed exceptions before returning through a native callback.

The ABI declarations and the ABI version in `src/Atlas.Binja/Core.cs`.

Submitting changes
------------------

Do not include generated files or random binaries.  Describe the behaviour changed, the evidence for the implementation, and the tests run.
