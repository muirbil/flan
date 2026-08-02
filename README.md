# 🍮 flan

**flan** is a lightweight package manager for Windows (x86_64), built from scratch in C++. 

Designed with raw performance, `flan` uses a custom binary database format and native WinAPI calls to deliver software without the bloat of traditional package managers. It solves the "symlink hell" problem found in tools like Scoop by enforcing a **Stable Path Architecture**.

> ⚠️ **Development Status: Pre-Alpha / Work in Progress**
>
>`flan` is currently under active development. The core binary parser, lazy JSON loading, and native archive extraction engines are implemented, but the remote package repository is currently being assembled. Expect breaking changes.

## Key Features

*   **Custom Binary Database (`core.flan`):** 
    Instead of parsing massive text files, `flan` uses a packed binary index. It uses standard memory offsets and direct struct casting for zero-cost deserialization. File validation is secured by a custom 8-byte magic number.
*   **Lazy Metadata Loading:**
    Heavy package data (URLs, versions, hashes) is fetched asynchronously via JSON (`nlohmann/json`) only at the exact moment of installation.
*   **Native Tooling:**
    Built specifically for x86_64 Windows. It uses `WinHTTP` for network requests and the native Windows `tar` utility for zero-dependency archive extraction.
*   **Global Shims:**
    Automatically generates transparent `.bat` wrappers in a centralized `bin` directory, making installed CLI tools instantly available globally via the system `PATH`.

## Architecture

`flan` is engineered with hardware sympathy:
- **Memory Efficiency:** Avoids full-file RAM allocation by `seekg` that jumps to extract data directly from the disk cache.

## Usage

Add the `~/.flan/bin` directory to your system `PATH` to start using installed tools.

```cmd
# Generate or fetch the latest binary index
flan sync

# List all available packages in the database
flan list

# Install a specific package (e.g., ripgrep)
flan install ripgrep
```
