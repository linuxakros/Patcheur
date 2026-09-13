#include <windows.h>
#include <shlwapi.h>
#include <shellapi.h>
#include <string>
#include <vector>
#include <fstream>
#include <iostream>
#include <cstdint>
#include <algorithm>
#include "compress.h"

#pragma comment(lib, "Shlwapi.lib")

static void print_usage() {
    std::wcout << L"Patcher - binary patch generator / applier\n\n";
    std::wcout << L"Generate patch:\n";
    std::wcout << L"  Patcher32.exe --generate <old> <new> <patch> [--bzip2]\n";
    std::wcout << L"Apply patch:\n";
    std::wcout << L"  Patcher32.exe --apply <old> <patch> <output>\n";
}

static bool read_file(const std::wstring& path, std::vector<unsigned char>& data) {
    std::ifstream f(path, std::ios::binary);
    if (!f) return false;
    f.seekg(0, std::ios::end);
    std::streamoff size = f.tellg();
    if (size < 0) return false;
    f.seekg(0, std::ios::beg);
    data.resize(static_cast<size_t>(size));
    if (!data.empty()) f.read(reinterpret_cast<char*>(data.data()), size);
    return static_cast<bool>(f) || data.empty();
}

static bool write_file(const std::wstring& path, const std::vector<unsigned char>& data) {
    std::ofstream f(path, std::ios::binary);
    if (!f) return false;
    if (!data.empty()) f.write(reinterpret_cast<const char*>(data.data()), data.size());
    return static_cast<bool>(f);
}

static uint32_t fnv1a(const unsigned char* data, size_t size) {
    uint32_t h = 2166136261u;
    for (size_t i = 0; i < size; ++i) {
        h ^= data[i];
        h *= 16777619u;
    }
    return h;
}

static int generate_patch(const wchar_t* oldPath, const wchar_t* newPath,
                          const std::wstring& patchPath, const std::wstring& workDir,
                          const std::wstring& label, bool useBzip2, bool verbose) {
    std::vector<unsigned char> oldData, newData;
    if (!read_file(oldPath, oldData) || !read_file(newPath, newData)) {
        std::wcerr << L"Unable to read input file.\n";
        return 1;
    }

    std::vector<unsigned char> payload = newData;
    std::string err;
    if (useBzip2 && !bz2_compress(newData, payload, err)) {
        std::cerr << err << '\n';
        return 1;
    }

    std::vector<unsigned char> patch;
    const char magic[] = "PTCH";
    patch.insert(patch.end(), magic, magic + 4);
    patch.push_back(1);
    patch.push_back(useBzip2 ? 1 : 0);
    uint64_t oldSize = oldData.size();
    uint64_t newSize = newData.size();
    uint32_t checksum = fnv1a(newData.data(), newData.size());
    for (int i = 0; i < 8; ++i) patch.push_back(static_cast<unsigned char>((oldSize >> (i * 8)) & 0xff));
    for (int i = 0; i < 8; ++i) patch.push_back(static_cast<unsigned char>((newSize >> (i * 8)) & 0xff));
    for (int i = 0; i < 4; ++i) patch.push_back(static_cast<unsigned char>((checksum >> (i * 8)) & 0xff));
    patch.insert(patch.end(), payload.begin(), payload.end());

    if (!write_file(patchPath, patch)) {
        std::wcerr << L"Unable to write patch.\n";
        return 1;
    }
    if (verbose) std::wcout << L"Patch generated: " << patchPath << L"\n";
    return 0;
}

static int apply_patch_file(const wchar_t* oldPath, const wchar_t* patchPath, const wchar_t* outputPath) {
    std::vector<unsigned char> oldData, patch;
    if (!read_file(oldPath, oldData) || !read_file(patchPath, patch)) {
        std::wcerr << L"Unable to read input file.\n";
        return 1;
    }
    if (patch.size() < 26 || std::string(reinterpret_cast<char*>(patch.data()), 4) != "PTCH") {
        std::wcerr << L"Invalid patch file.\n";
        return 1;
    }
    bool useBzip2 = patch[5] != 0;
    uint64_t oldSize = 0, newSize = 0;
    for (int i = 0; i < 8; ++i) oldSize |= uint64_t(patch[6 + i]) << (i * 8);
    for (int i = 0; i < 8; ++i) newSize |= uint64_t(patch[14 + i]) << (i * 8);
    uint32_t checksum = 0;
    for (int i = 0; i < 4; ++i) checksum |= uint32_t(patch[22 + i]) << (i * 8);
    if (oldData.size() != oldSize) {
        std::wcerr << L"Input file does not match the patch.\n";
        return 1;
    }

    std::vector<unsigned char> payload(patch.begin() + 26, patch.end()), output;
    std::string err;
    if (useBzip2) {
        if (!bz2_decompress(payload, output, err)) {
            std::cerr << err << '\n';
            return 1;
        }
    } else {
        output = std::move(payload);
    }
    if (output.size() != newSize || fnv1a(output.data(), output.size()) != checksum) {
        std::wcerr << L"Patch verification failed.\n";
        return 1;
    }
    if (!write_file(outputPath, output)) {
        std::wcerr << L"Unable to write output file.\n";
        return 1;
    }
    std::wcout << L"Patch applied: " << outputPath << L"\n";
    return 0;
}

int wmain(int argc, wchar_t* argv[]) {
    if (argc < 2) {
        print_usage();
        return 1;
    }

    std::wstring command = argv[1];
    if (command == L"--generate" && argc >= 5) {
        bool bzip2 = false;
        bool verbose = false;
        for (int i = 5; i < argc; ++i) {
            if (std::wstring(argv[i]) == L"--bzip2") bzip2 = true;
            if (std::wstring(argv[i]) == L"--verbose") verbose = true;
        }
        return generate_patch(argv[2], argv[3], argv[4], L"", L"", bzip2, verbose);
    }
    if (command == L"--apply" && argc >= 5) {
        return apply_patch_file(argv[2], argv[3], argv[4]);
    }
    print_usage();
    return 1;
}
