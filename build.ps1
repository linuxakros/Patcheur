$ErrorActionPreference = "Stop"

$root = $PSScriptRoot
$srcDir = Join-Path $root "src"
$outputDir = Join-Path $root "build"
$tempDir = Join-Path $root "_build"

# ---------------------------------------------------------------------------
# Validate the source tree.
# ---------------------------------------------------------------------------
foreach ($file in @("main.cpp", "compress.cpp", "compress.h")) {
    $path = Join-Path $srcDir $file
    if (-not (Test-Path $path)) {
        throw "Missing source file: $path"
    }
}

# The build output directory is persistent: final EXEs are kept here.
if (Test-Path $outputDir) {
    Remove-Item $outputDir -Recurse -Force
}
New-Item -ItemType Directory -Path $outputDir | Out-Null

# Temporary compiler/download files are isolated here and always removed.
if (Test-Path $tempDir) {
    Remove-Item $tempDir -Recurse -Force
}
New-Item -ItemType Directory -Path $tempDir | Out-Null

try {
    $bzip2Version = "1.0.8"
    $bzip2Url = "https://sourceware.org/pub/bzip2/bzip2-$bzip2Version.tar.gz"
    $bzip2Sha512 = "083f5e675d73f3233c7930ebe20425a533feedeaaa9d8cc86831312a6581cefbe6ed0d08d2fa89be81082f2a5abdabca8b3c080bf97218a1bd59dc118a30b9f3"

    $bzip2Archive = Join-Path $tempDir "bzip2-$bzip2Version.tar.gz"
    $bzip2Source = Join-Path $tempDir "bzip2-$bzip2Version"
    $manifest = Join-Path $tempDir "Patcher.manifest"

    # Generate a mt.exe-compatible UTF-8 manifest without a BOM.
    $manifestXml = @'
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0">
  <trustInfo xmlns="urn:schemas-microsoft-com:asm.v3">
    <security>
      <requestedPrivileges>
        <requestedExecutionLevel level="asInvoker" uiAccess="false"/>
      </requestedPrivileges>
    </security>
  </trustInfo>
</assembly>
'@
    $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllText($manifest, $manifestXml, $utf8NoBom)
    Write-Host "Manifest generated."

    $vswhere = Join-Path ${env:ProgramFiles(x86)} "Microsoft Visual Studio\Installer\vswhere.exe"
    if (-not (Test-Path $vswhere)) {
        Write-Host ""
        Write-Host "Visual Studio C++ Build Tools were not found." -ForegroundColor Red
        Write-Host ""
        Write-Host "Patcheur requires the Microsoft C++ build tools to compile the project."
        Write-Host ""
        Write-Host "Please install:"
        Write-Host "  - Visual Studio Build Tools"
        Write-Host "  - Desktop development with C++"
        Write-Host "  - MSVC C++ build tools for x86/x64"
        Write-Host "  - Windows SDK"
        Write-Host ""
        Write-Host "Official download:"
        Write-Host "  https://visualstudio.microsoft.com/downloads/"
        Write-Host ""
        throw "Required C++ build tools are missing. Install them and run this script again."
    }

    $vs = & $vswhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
    if (-not $vs) {
        throw "Required Visual Studio C++ Build Tools are missing. Install Desktop development with C++ from https://visualstudio.microsoft.com/downloads/ and run this script again."
    }

    Write-Host "Downloading bzip2 $bzip2Version..."
    Invoke-WebRequest -Uri $bzip2Url -OutFile $bzip2Archive
    $actualSha512 = (Get-FileHash -Algorithm SHA512 -Path $bzip2Archive).Hash.ToLowerInvariant()
    if ($actualSha512 -ne $bzip2Sha512) { throw "The downloaded bzip2 archive failed SHA-512 verification." }
    Write-Host "bzip2 SHA-512 verified."
    tar -xzf $bzip2Archive -C $tempDir

    function Invoke-Build {
        param([ValidateSet("x86", "x64")][string]$Arch, [string]$OutName)

        Write-Host "`n=== Building $OutName ($Arch) ===" -ForegroundColor Cyan
        $archArg = if ($Arch -eq "x86") { "-arch=x86 -host_arch=x86" } else { "-arch=x64 -host_arch=x64" }

        cmd.exe /c "`"$vs\Common7\Tools\VsDevCmd.bat`" $archArg >nul && set" | ForEach-Object {
            if ($_ -match "^(.*?)=(.*)$") { Set-Item -Path "env:$($matches[1])" -Value $matches[2] }
        }
        if (-not (Get-Command cl.exe -ErrorAction SilentlyContinue)) { throw "cl.exe was not found for $Arch." }

        $objDir = Join-Path $tempDir "obj-$Arch"
        New-Item -ItemType Directory -Path $objDir -Force | Out-Null
        $commonArgs = @("/nologo", "/MT", "/O2", "/EHsc", "/utf-8", "/D_WIN32_WINNT=0x0600", "/DWIN32_LEAN_AND_MEAN", "/DNOMINMAX", "/I$root", "/I$bzip2Source")

        & cl.exe @commonArgs /c (Join-Path $srcDir "main.cpp") "/Fo:$(Join-Path $objDir 'main.obj')"
        if ($LASTEXITCODE -ne 0) { throw "Compilation failed for main.cpp ($Arch)." }
        & cl.exe @commonArgs /c (Join-Path $srcDir "compress.cpp") "/Fo:$(Join-Path $objDir 'patcheur_compress.obj')"
        if ($LASTEXITCODE -ne 0) { throw "Compilation failed for Patcheur compress.cpp ($Arch)." }

        $bzip2Objects = @()
        foreach ($cFile in @("blocksort.c", "compress.c", "crctable.c", "decompress.c", "huffman.c", "randtable.c", "bzlib.c")) {
            $objectPath = Join-Path $objDir ([IO.Path]::GetFileNameWithoutExtension($cFile) + "_bz2.obj")
            & cl.exe @commonArgs /c (Join-Path $bzip2Source $cFile) "/Fo:$objectPath"
            if ($LASTEXITCODE -ne 0) { throw "Compilation failed for bzip2 $cFile ($Arch)." }
            $bzip2Objects += $objectPath
        }

        $objects = @((Join-Path $objDir "main.obj"), (Join-Path $objDir "patcheur_compress.obj")) + $bzip2Objects
        $outPath = Join-Path $outputDir $OutName
        & link.exe @objects "/SUBSYSTEM:CONSOLE,6.00" "/MANIFEST:EMBED" "/MANIFESTINPUT:$manifest" "/OUT:$outPath"
        if ($LASTEXITCODE -ne 0) { throw "Link failed for $OutName." }
        if (-not (Test-Path $outPath)) { throw "Link reported success, but the output was not created: $outPath" }
        Write-Host "Build successful: $outPath" -ForegroundColor Green
    }

    Invoke-Build -Arch x86 -OutName "Patcher32.exe"
    Invoke-Build -Arch x64 -OutName "Patcher64.exe"
    Write-Host "`nBoth builds completed successfully." -ForegroundColor Green
    Write-Host "Output directory: $outputDir" -ForegroundColor Green
}
finally {
    if (Test-Path $tempDir) { Remove-Item $tempDir -Recurse -Force -ErrorAction SilentlyContinue }
}
