# Patcheur

## Requirements

- Windows
- PowerShell
- Internet access
- Microsoft Visual Studio Build Tools with C++ support

Install the **Desktop development with C++** workload, including the MSVC C++ build tools for x86/x64 and a Windows SDK.

Official download:
https://visualstudio.microsoft.com/downloads/

The build script does not install Visual Studio or the C++ toolchain automatically. If the required tools are not found, it displays installation instructions and stops.

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
