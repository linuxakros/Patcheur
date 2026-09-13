# Patcheur

## What is Patcheur?

Patcheur is a Windows binary patch utility. It can generate a patch by comparing an original executable with a modified executable, then apply that patch to another copy of the original file.

Patches can optionally be compressed with **bzip2 1.0.8**.

Patcheur provides separate **x86 (32-bit)** and **x64 (64-bit)** executables.

## Requirements

- Windows
- PowerShell
- Internet access for the build process
- Microsoft Visual Studio Build Tools with C++ support

Install the **Desktop development with C++** workload, including the MSVC C++ build tools for x86/x64 and a Windows SDK.

Official download:
https://visualstudio.microsoft.com/downloads/

The build script does not install Visual Studio or the C++ toolchain automatically. If the required tools are not found, it displays installation instructions and stops.

## Using Patcheur

### Generate a patch

Compare an original file with a modified file:

```text
Patcher64.exe -g original.exe patched.exe
```

This generates:

```text
original.exe.patch
```

To generate a compressed patch:

```text
Patcher64.exe -g -c original.exe patched.exe
```

This generates:

```text
original.exe.patch.bz2
```

The same commands can be used with `Patcher32.exe` for 32-bit environments.

### Apply a patch

Apply a generated patch to the original file:

```text
Patcher64.exe -p original.exe original.exe.patch
```

By default, the patched file is created as:

```text
original_patched.exe
```

### Patch options

```text
-g, -generate       Generate a patch
-p, -patch          Apply a patch
-c, -compress       Compress the generated patch with bzip2
-b, -brute          Generate brute compact patch (no original bytes)
--debug             Show detailed timing for each process stage
-n, -name <name>    Set the patch name
-d, -description    Set the patch description
```

For help, run:

```text
Patcher64.exe
```

## Build

Patcheur is built for both **x86** and **x64** using the Microsoft Visual C++ toolchain.

Run the following command from the project root:

```powershell
powershell -ExecutionPolicy Bypass -File .\build.ps1
```

The build script:

1. Downloads the required bzip2 source package.
2. Verifies the downloaded archive.
3. Generates the application manifest.
4. Builds the x86 version.
5. Builds the x64 version.
6. Places generated executables under `build\`.
7. Removes temporary and intermediate files when they are no longer needed.

No generated binaries, object files, or temporary build artifacts are required in the source tree.

## Project layout

```text
Patcheur/
├── .gitignore
├── build.ps1
├── README.md
└── src/
    ├── main.cpp
    ├── compress.cpp
    └── compress.h
```

## Build output

The build generates:

```text
build/
├── Patcher32.exe
└── Patcher64.exe
```

The `build\` directory contains the final generated executables and should not be used for source code. The build script reads all project sources from `src\`.

All compiler intermediate files, including `.obj` files, are created temporarily under the build process and removed automatically. The final `Patcher32.exe` and `Patcher64.exe` remain in `build\`.

## Git

Generated build output is ignored by Git. The repository contains source code and build scripts only.

The generated executables are placed in `build\` and are not committed to the repository.
