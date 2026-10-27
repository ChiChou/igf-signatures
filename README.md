# IGF Signatures

Offline SQLite hook templates for Android and Apple platforms. The generator extracts C declarations using libclang from the Android NDK and installed Xcode SDKs, supplements Android platform libraries with pinned AOSP ABI dumps, and records kernel syscall metadata.

These are editable starting points for hooks. The database preserves original C spelling and canonical types alongside Frida types and display hints. For example, `const char *` becomes Frida `pointer` with an `utf8` hint, while `void *` remains an address. Typedefs and qualifiers remain available for future converters. Structs, unusual scalar types, and unresolved ABI types currently receive an approximate pointer template. Objective-C method signatures and Java methods are not extracted; C functions from those frameworks are included.

## Build

Requirements: macOS with Xcode selected using `xcode-select`, Python 3.10+, and the NDK version in `sources.json`. No Python packages are required. `LIBCLANG` may point to a specific libclang dynamic library; otherwise the generator uses Xcode's bundled copy.

```sh
export ANDROID_NDK_HOME="$HOME/Library/Android/sdk/ndk/28.2.13676358"
python3 -m unittest discover -s tests
python3 generator/build.py --version v0.1.0
python3 generator/check.py dist/signatures.db
```

Outputs: `dist/signatures.db`, `signatures.db.gz`, `manifest.json`, and `diagnostics.json`. SDK headers are never included in release artifacts. Source downloads are cached in `.cache/`; their revisions are pinned in `sources.json`. Apple SDK and compiler versions are recorded in the database. A given release artifact is pinned by its SHA-256, rather than assuming byte-for-byte reproduction across Xcode releases.

`--only android` and `--only apple` build partial databases for development. Release builds omit this flag. The validation command requires both platforms.

## Schema

`schema.sql` is authoritative. `PRAGMA user_version` identifies the schema; `metadata.version` identifies the dataset release.

- `sources`: SDK version, source revision, URL, compiler and platform.
- `types`: original C spelling, canonical C type, JSON-encoded Frida type, byte size, display hint and approximate flag. JSON permits future Frida struct-type arrays without losing existing declarations.
- `functions`: library/export name, architecture, source, header, return type, variadic flag and function/syscall kind.
- `parameters`: ordered named parameters referencing `types`.
- `syscalls`: architecture and number mapped to a function signature when known. Unresolved or historical entries retain their names and numbers without inventing prototypes.

The lookup index starts with platform and symbol. Functions retain separate rows for different architectures and SDK sources. Types are deduplicated, including canonical spelling and width, so 32-bit and 64-bit typedef variants remain distinct.

```sql
SELECT f.module, f.symbol, p.position, p.name,
       t.c_spelling, t.canonical_c, t.frida_type, t.display_hint
FROM functions f
JOIN parameters p ON p.function_id = f.id
JOIN types t ON t.id = p.type_id
WHERE f.platform = 'android' AND f.arch = 'arm64'
  AND f.module = 'libc.so' AND f.symbol = 'puts'
ORDER BY p.position;
```

Display hints are defaults, not guarantees: a `char *` can point to binary data. Raw syscall calling conventions differ from libc wrappers; syscall entries must not be used as ordinary exported function hooks. Variadic trailing arguments, floating-point register decoding, and aggregate ABI lowering need caller-specific handling.

## Releases and updates

GitHub Actions runs on a macOS hosted runner with Xcode. It installs the pinned NDK, tests conversions, builds SQLite, checks integrity and coverage, and uploads artifacts. `v*` tags publish immutable release assets. A monthly schedule publishes uniquely named snapshot prereleases using the runner's installed Xcode and the pinned Android source inputs. Update `sources.json` explicitly to advance Android inputs.

Consumers pin a release tag and both the compressed and uncompressed SHA-256 values from `manifest.json`. They download only the database during setup; no SDK, compiler, network service or API key is needed at runtime. Do not replace existing release assets. Publish a new version for every change.

## Attribution

Generator code is MIT-licensed. See `NOTICE.txt` and each source's upstream notices for SDK and library provenance. Source headers and implementation code are not redistributed.
