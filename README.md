# flan

flan is a lightweight package manager for Windows, written in C++. It is a single `flan.exe` that does not need .NET, PowerShell or administrator rights. It is meant for weak machines and slow connections.

## Installation

1. Download `flan-x64.exe` (64-bit Windows) or `flan-x86.exe` (32-bit Windows) from the [v0.4.1 release](https://github.com/muirbil/flan/releases/tag/v0.4.1).
2. Run it once with `setup` from a console:

   ```
   flan-x64.exe setup
   ```

   `setup` copies the running executable to `%USERPROFILE%\.flan\bin\flan.exe` under that name, whatever the downloaded file was called. It then adds that `bin` folder to your user `PATH` and reports what it did. The downloaded file is not needed afterwards.
3. Open a new console window. Running consoles keep the old `PATH`.
4. Fetch the package index:

   ```
   flan sync
   ```

flan keeps everything in `%USERPROFILE%\.flan`. To use another folder, set the `FLAN_HOME` environment variable to an absolute path before running `setup`, and keep it set: flan reads it on every run.

## Commands

| Command | What it does | Example |
|---|---|---|
| `sync` | Downloads the package index, or nothing if it has not changed. | `flan sync` |
| `list` | Lists the packages available in the index. | `flan list` |
| `install <package>...` | Installs packages, or updates those for which the index has a different build. | `flan install ripgrep fd` |
| `upgrade [package...]` | Updates the named packages. Without arguments: every installed package whose build changed, then flan itself. | `flan upgrade` |
| `uninstall <package>...` | Removes packages and their commands. | `flan uninstall ripgrep fd` |
| `installed` | Lists the installed packages. | `flan installed` |
| `setup [--remove]` | Puts `flan.exe` into `bin\` and `bin\` into your user `PATH`; `--remove` takes it out of `PATH`. | `flan setup --remove` |
| `--version` | Prints the version and architecture. | `flan --version` |
| `--help` | Prints the list of commands. | `flan --help` |

`<package>` is a required argument, `[ ]` marks an optional one, `...` means it can be repeated.

`install`, `uninstall` and `upgrade` handle each package separately: if one fails, the others are still processed, and the exit code is that of the first failure.

`flan upgrade flan` updates flan itself. `install flan` and `uninstall flan` are refused: flan is not installed as a package.

Exit codes:

| Code | Meaning |
|---|---|
| 0 | success |
| 1 | other error |
| 2 | wrong arguments |
| 3 | network error |
| 4 | integrity error (hash, signature, index rollback) |
| 5 | package not found |
| 6 | another flan is running |

## How it works

- **Index.** All package metadata is one file, `index.flan`, built by `flan-build` from the manifests in [flan-packages](https://github.com/muirbil/flan-packages). It is compressed and signed. `flan sync` downloads it with a conditional request, so an unchanged index costs no download.
- **Installation.** flan picks the build for the system architecture: x64 on 64-bit Windows, falling back to x86. It downloads the archive (a zip or a single `.exe`) once into `cache\`, checking its size and SHA-256 against the index while downloading; an interrupted download resumes. It unpacks the archive with its own zip reader, with no external tools.
- **Versioned folders.** Each version goes into its own folder, `apps\<package>\<version>\`, so a package can be updated while its program is running. The old folder is removed afterwards, or on a later run if it is still in use.
- **Shims.** Each command of a package is a small `bin\<command>.exe` that starts the real program with the same arguments and returns its exit code. Only `bin\` is in `PATH`. A command that belongs to another package, or to a file flan did not create, is never overwritten.
- **Outside `.flan`,** flan writes only your user `PATH` (`HKCU\Environment\Path`), and only through `flan setup` and `flan setup --remove`.

See [DESIGN.md](DESIGN.md) for details.

## Security

What flan checks:

- **Index signature.** The index is signed with ECDSA P-256. The public keys are compiled into `flan.exe`. The signature is checked before any byte of the index is unpacked or parsed, both when it is downloaded and every time the local copy is read. Unsigned indexes are always refused.
- **Rollback.** An index older than the last accepted one is refused. So is an index signed with a key older than the last accepted key.
- **SHA-256.** Every downloaded archive and `.exe` must match the SHA-256 in the signed index.
- **Archives.** Paths that leave the target folder, absolute paths, alternate data streams, device names and symbolic links are refused before anything is written. The total unpacked size and the compression ratio are limited.
- **No code runs during installation:** no scripts, no installers.
- **Self-update.** The new `flan.exe` must match the SHA-256 in the signed index and report the version the index names before it replaces the old one.

flan does not need administrator rights and warns when it is run as administrator.

Outside the threat model: a malicious program published by its own author, and a compromise of the index author's machine together with the signing key.

## Requirements

- Windows 10 or 11, x64 or x86.
- Windows 7 SP1 and 8.1 need update KB2999226 (Universal C Runtime). Not tested.

## Building from source

Requirements: Visual Studio 2022 with the "Desktop development with C++" workload (toolset v143) and a Windows 10 SDK.

Open `flan.sln`. The solution has four configurations: `Debug` and `Release`, each for `x64` and `x86`. It contains four projects:

- `flan` — the client;
- `shim` — the command shim, embedded into `flan.exe`;
- `flan-build` — the index generator;
- `flan-tests` — the tests.

From a Developer Command Prompt:

```
msbuild flan.sln /p:Configuration=Release /p:Platform=x64
```

The output goes to `bin\x64\Release\` (`bin\Win32\Release\` for x86).

Tests:

```
bin\x64\Release\flan-tests.exe
```

The tests print failures and a summary, and exit with code 0 when everything passes. Add `-v` to see every check.

Debug builds also trust the test signing keys in `tests\keys`. Release builds do not.

## Status

Pre-alpha. Formats and commands may still change.

## Contributing

- To request a package, open an issue in [flan-packages](https://github.com/muirbil/flan-packages/issues).
- To add a package, open a pull request there with a single `packages/<name>.json`. Do not include `index.flan`: only the maintainer builds and signs it.
- To report a bug in flan itself, open an issue in [this repository](https://github.com/muirbil/flan/issues).
