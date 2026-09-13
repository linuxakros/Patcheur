// Patcher v21 - $OFFSET compact operations
// Auto-detects 32-bit / 64-bit and adjusts memory limits accordingly
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0600
#endif

#if defined(_WIN64) || defined(_M_X64) || defined(_M_AMD64)
#define PATCHER_64BIT 1
#define PATCHER_NAME L"Patcher64"
#define PATCHER_NAME_A "Patcher64"
#else
#define PATCHER_64BIT 0
#define PATCHER_NAME L"Patcher32"
#define PATCHER_NAME_A "Patcher32"
#endif

#include <windows.h>
#include <stdint.h>
#include <stdio.h>
#include <string>
#include <vector>
#include <fstream>
#include <sstream>
#include <iostream>
#include <iomanip>
#include <cstring>
#include <algorithm>
#include <unordered_map>
#include <functional>
#include <chrono>
#include <thread>
#include <mutex>
#include <atomic>
#include <new>
#include "compress.h"

static bool g_debug = false;
static const std::chrono::steady_clock::time_point g_process_start = std::chrono::steady_clock::now();

static void debug_report(const char* name,
                         const std::chrono::steady_clock::time_point& start)
{
    if (!g_debug)
        return;

    const double seconds = std::chrono::duration<double>(
        std::chrono::steady_clock::now() - start).count();

    std::cerr << "[DEBUG] " << name << " : "
              << std::fixed << std::setprecision(3)
              << seconds << " s\n";
}

struct Sha256Ctx {
    uint32_t state[8];
    uint64_t bitlen;
    uint8_t data[64];
    size_t datalen;
};

static uint32_t rotr(uint32_t x, uint32_t n) {
    return (x >> n) | (x << (32 - n));
}

static const uint32_t K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

static void sha_transform(Sha256Ctx* c, const uint8_t d[64]) {
    uint32_t m[64];
    for (int i = 0; i < 16; ++i) {
        m[i] = (uint32_t)d[i * 4] << 24 |
               (uint32_t)d[i * 4 + 1] << 16 |
               (uint32_t)d[i * 4 + 2] << 8 |
               (uint32_t)d[i * 4 + 3];
    }
    for (int i = 16; i < 64; ++i) {
        const uint32_t s0 = rotr(m[i - 15], 7) ^ rotr(m[i - 15], 18) ^ (m[i - 15] >> 3);
        const uint32_t s1 = rotr(m[i - 2], 17) ^ rotr(m[i - 2], 19) ^ (m[i - 2] >> 10);
        m[i] = m[i - 16] + s0 + m[i - 7] + s1;
    }

    uint32_t a = c->state[0], b = c->state[1], cc = c->state[2], dd = c->state[3];
    uint32_t e = c->state[4], f = c->state[5], g = c->state[6], h = c->state[7];

    for (int i = 0; i < 64; ++i) {
        const uint32_t S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
        const uint32_t ch = (e & f) ^ ((~e) & g);
        const uint32_t t1 = h + S1 + ch + K[i] + m[i];
        const uint32_t S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
        const uint32_t maj = (a & b) ^ (a & cc) ^ (b & cc);
        const uint32_t t2 = S0 + maj;
        h = g; g = f; f = e; e = dd + t1; dd = cc; cc = b; b = a; a = t1 + t2;
    }

    c->state[0] += a; c->state[1] += b; c->state[2] += cc; c->state[3] += dd;
    c->state[4] += e; c->state[5] += f; c->state[6] += g; c->state[7] += h;
}

static void sha_init(Sha256Ctx* c) {
    c->datalen = 0; c->bitlen = 0;
    c->state[0] = 0x6a09e667; c->state[1] = 0xbb67ae85;
    c->state[2] = 0x3c6ef372; c->state[3] = 0xa54ff53a;
    c->state[4] = 0x510e527f; c->state[5] = 0x9b05688c;
    c->state[6] = 0x1f83d9ab; c->state[7] = 0x5be0cd19;
}

static void sha_update(Sha256Ctx* c, const uint8_t* d, size_t len) {
    for (size_t i = 0; i < len; ++i) {
        c->data[c->datalen++] = d[i];
        if (c->datalen == 64) { sha_transform(c, c->data); c->bitlen += 512; c->datalen = 0; }
    }
}

static void sha_final(Sha256Ctx* c, uint8_t out[32]) {
    size_t i = c->datalen;
    c->data[i++] = 0x80;
    if (i > 56) { while (i < 64) c->data[i++] = 0; sha_transform(c, c->data); i = 0; }
    while (i < 56) c->data[i++] = 0;
    c->bitlen += (uint64_t)c->datalen * 8;
    for (int j = 7; j >= 0; --j) c->data[56 + (7 - j)] = (uint8_t)(c->bitlen >> (j * 8));
    sha_transform(c, c->data);
    for (i = 0; i < 8; ++i) {
        out[i * 4] = (uint8_t)(c->state[i] >> 24);
        out[i * 4 + 1] = (uint8_t)(c->state[i] >> 16);
        out[i * 4 + 2] = (uint8_t)(c->state[i] >> 8);
        out[i * 4 + 3] = (uint8_t)c->state[i];
    }
}

static bool utf8_to_wide(const std::string& in, std::wstring& out) {
    if (in.empty()) {
        out.clear();
        return true;
    }

    const int count = MultiByteToWideChar(
        CP_UTF8, MB_ERR_INVALID_CHARS, in.data(), static_cast<int>(in.size()),
        NULL, 0);

    if (count <= 0) {
        return false;
    }

    out.resize(static_cast<size_t>(count));
    return MultiByteToWideChar(
        CP_UTF8, MB_ERR_INVALID_CHARS, in.data(), static_cast<int>(in.size()),
        &out[0], count) > 0;
}

static std::string sha256_bytes(const uint8_t* data, size_t len) {
    Sha256Ctx c;
    uint8_t out[32];
    sha_init(&c);
    if (len != 0) {
        sha_update(&c, data, len);
    }
    sha_final(&c, out);

    static const char* hexChars = "0123456789abcdef";
    std::string result;
    result.reserve(64);
    for (int i = 0; i < 32; ++i) {
        result.push_back(hexChars[out[i] >> 4]);
        result.push_back(hexChars[out[i] & 15]);
    }
    return result;
}

static bool wide_to_utf8(const std::wstring& in, std::string& out) {
    if (in.empty()) {
        out.clear();
        return true;
    }

    const int count = WideCharToMultiByte(
        CP_UTF8, 0, in.data(), static_cast<int>(in.size()),
        NULL, 0, NULL, NULL);

    if (count <= 0) {
        return false;
    }

    out.resize(static_cast<size_t>(count));

    return WideCharToMultiByte(
        CP_UTF8, 0, in.data(), static_cast<int>(in.size()),
        &out[0], count, NULL, NULL) > 0;
}

static std::string sha256_patch_text(const std::string& text) {
    std::string canonical;
    canonical.reserve(text.size());

    size_t pos = 0;
    while (pos < text.size()) {
        size_t end = text.find('\n', pos);
        if (end == std::string::npos) end = text.size();

        const std::string line = text.substr(pos, end - pos);
        const size_t first = line.find_first_not_of(" \t\r");
        const std::string key = "patch_sha256=";

        if (first != std::string::npos && line[first] != '#' &&
            line.compare(first, key.size(), key) != 0) {
            canonical.append(line);
        }

        pos = (end == text.size()) ? end : end + 1;
    }

    return sha256_bytes(reinterpret_cast<const uint8_t*>(canonical.data()), canonical.size());
}

static std::string sha256(const std::vector<uint8_t>& data) {
    Sha256Ctx c; uint8_t out[32]; sha_init(&c);
    if (!data.empty()) sha_update(&c, &data[0], data.size());
    sha_final(&c, out);
    static const char* h = "0123456789abcdef";
    std::string result; result.reserve(64);
    for (int i = 0; i < 32; ++i) { result.push_back(h[out[i] >> 4]); result.push_back(h[out[i] & 15]); }
    return result;
}

static bool read_all(const wchar_t* path, std::vector<uint8_t>& data) {
    std::ifstream f(path, std::ios::binary);
    if (!f) return false;
    data.assign((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
    return !!f;
}

static void print_usage() {
    std::wcerr << PATCHER_NAME << L" - Binary patch utility\n\n";

    std::wcerr << L"Usage:\n";
    std::wcerr << L"  " << PATCHER_NAME << L" -g <original> <patched> [options]\n";
    std::wcerr << L"  " << PATCHER_NAME << L" -p <file> <patch> [output]\n\n";

    std::wcerr << L"Options:\n";
    std::wcerr << L"  -g, -generate       Generate a patch\n";
    std::wcerr << L"  -p, -patch          Apply a patch\n";
    std::wcerr << L"  -c, -compress       Compress the generated patch with bzip2\n";
    std::wcerr << L"  -b, -brute          Generate brute compact patch (no original bytes)\n";
    std::wcerr << L"  --debug             Show detailed timing for each process stage\n";
    std::wcerr << L"  -n, -name <name>    Set the patch name\n";
    std::wcerr << L"  -d, -description <description>\n";
    std::wcerr << L"                      Set the patch description\n\n";

    std::wcerr << L"Examples:\n";
    std::wcerr << L"  " << PATCHER_NAME << L" -g original.exe patched.exe\n";
    std::wcerr << L"  " << PATCHER_NAME << L" -g -c original.exe patched.exe\n";
    std::wcerr << L"  " << PATCHER_NAME << L" -g original.exe patched.exe -n \"My Patch\"\n";
    std::wcerr << L"  " << PATCHER_NAME << L" -p original.exe original.exe.patch\n\n";

    std::wcerr << L"Default output:\n";
    std::wcerr << L"  Generate: <original>.patch\n";
    std::wcerr << L"  Generate + -c: <original>.patch.bz2\n";
    std::wcerr << L"  Apply: <base>_patched.<extension>\n";
}

static std::string make_hex(const std::vector<uint8_t>& data, size_t begin, size_t end) {
    static const char* h = "0123456789ABCDEF";
    std::ostringstream out;
    for (size_t i = begin; i < end; ++i) {
        if (i != begin) out << ' ';
        out << h[data[i] >> 4] << h[data[i] & 15];
    }
    return out.str();
}


static void print_wline(const std::wstring& text) {
    DWORD written = 0;
    HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
    if (h != INVALID_HANDLE_VALUE && h != NULL) {
        DWORD mode = 0;
        if (GetConsoleMode(h, &mode)) {
            WriteConsoleW(h, text.c_str(), static_cast<DWORD>(text.size()), &written, NULL);
            WriteConsoleW(h, L"\r\n", 2, &written, NULL);
            return;
        }
    }
    std::wcout << text << L"\n";
}

struct ExecutionTimer {
    std::chrono::steady_clock::time_point start;

    ExecutionTimer() : start(std::chrono::steady_clock::now()) {
        SYSTEMTIME st;
        GetLocalTime(&st);
        wchar_t buf[64];
        swprintf_s(buf, L"%04u-%02u-%02u %02u:%02u:%02u",
                   st.wYear, st.wMonth, st.wDay,
                   st.wHour, st.wMinute, st.wSecond);
        // print_wline(std::wstring(L"Start : ") + buf);
    }

    ~ExecutionTimer() {
        SYSTEMTIME st;
        GetLocalTime(&st);
        wchar_t buf[64];
        swprintf_s(buf, L"%04u-%02u-%02u %02u:%02u:%02u",
                   st.wYear, st.wMonth, st.wDay,
                   st.wHour, st.wMinute, st.wSecond);

        const double seconds = std::chrono::duration<double>(
            std::chrono::steady_clock::now() - start).count();

        // print_wline(std::wstring(L"End   : ") + buf);

        wchar_t dur[64];
        swprintf_s(dur, L"  Duration : %.3f s", seconds);
        print_wline(dur);

        if (g_debug) {
            std::cerr << "[DEBUG] total process time : "
                      << std::fixed << std::setprecision(3)
                      << seconds << " s\n";
        }
    }
};

static std::wstring ensure_patch_extension(const std::wstring& path) {
    if (path.size() >= 6) {
        const std::wstring tail = path.substr(path.size() - 6);
        if (_wcsicmp(tail.c_str(), L".patch") == 0) {
            return path;
        }
    }
    return path + L".patch";
}

static std::wstring ensure_compressed_patch_extension(const std::wstring& path) {
    if (path.size() >= 10) {
        const std::wstring tail = path.substr(path.size() - 10);
        if (_wcsicmp(tail.c_str(), L".patch.bz2") == 0) {
            return path;
        }
    }
    if (path.size() >= 6) {
        const std::wstring tail = path.substr(path.size() - 6);
        if (_wcsicmp(tail.c_str(), L".patch") == 0) {
            return path + L".bz2";
        }
    }
    return path + L".patch.bz2";
}

static std::wstring normalize_option(const std::wstring& arg) {
    if (arg.size() >= 2 && arg[0] == L'-' && arg[1] == L'-') {
        return arg.substr(1);
    }
    return arg;
}

static bool has_bz2_extension(const std::wstring& path) {
    if (path.size() < 4) return false;
    const std::wstring tail = path.substr(path.size() - 4);
    return _wcsicmp(tail.c_str(), L".bz2") == 0;
}

static std::wstring default_patched_output_path(const std::wstring& input) {
    const size_t slash = input.find_last_of(L"\\/");
    const size_t dot = input.find_last_of(L'.');

    const bool hasExtension =
        dot != std::wstring::npos &&
        (slash == std::wstring::npos || dot > slash) &&
        dot + 1 < input.size();

    if (hasExtension) {
        return input.substr(0, dot) + L"_patched" + input.substr(dot);
    }

    return input + L"_patched";
}

static std::wstring trimw(const std::wstring& s) {
    const size_t a = s.find_first_not_of(L" \t\r\n");
    if (a == std::wstring::npos) {
        return L"";
    }
    const size_t b = s.find_last_not_of(L" \t\r\n");
    return s.substr(a, b - a + 1);
}

static std::string lowerascii(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(), [](char c) {
        return static_cast<char>(tolower(static_cast<unsigned char>(c)));
    });
    return s;
}

static bool parse_u64(const std::wstring& s, uint64_t& out) {
    const std::wstring t = trimw(s);
    const int base = (t.size() > 2 && t[0] == L'0' && (t[1] == L'x' || t[1] == L'X')) ? 16 : 10;
    wchar_t* end = NULL;
    out = wcstoull(t.c_str(), &end, base);
    return end != NULL && *end == 0;
}

static bool hexbyte(const std::wstring& s, std::vector<uint8_t>& out) {
    out.clear();
    std::wistringstream is(s);
    std::wstring token;

    while (is >> token) {
        if (token.size() != 2) {
            return false;
        }

        wchar_t* end = NULL;
        const unsigned long value = wcstoul(token.c_str(), &end, 16);
        if (end == NULL || *end != 0 || value > 255) {
            return false;
        }
        out.push_back(static_cast<uint8_t>(value));
    }

    return true;
}


struct Operation {
    std::wstring type;
    uint64_t offset;
    std::vector<uint8_t> original;
    std::vector<uint8_t> patched;
    bool hasOriginal;
    bool hasPatched;
    bool hasType;
    bool lengthOnly;
    size_t deleteLength;
};

struct Patch {
    Patch() : formatVersion(0) {}
    int formatVersion;
    std::wstring name;
    std::wstring description;
    std::string targetSha;
    std::string patchedSha;
    std::string patchSha;
    std::vector<Operation> ops;
};

static bool hexbyte_compact(const std::wstring& s, std::vector<uint8_t>& out) {
    out.clear();
    if (s.empty() || (s.size() & 1) != 0) return false;
    out.reserve(s.size() / 2);
    for (size_t i = 0; i < s.size(); i += 2) {
        const wchar_t a = s[i];
        const wchar_t b = s[i + 1];
        const int ha = (a >= L'0' && a <= L'9') ? a - L'0' :
                       (a >= L'A' && a <= L'F') ? a - L'A' + 10 :
                       (a >= L'a' && a <= L'f') ? a - L'a' + 10 : -1;
        const int hb = (b >= L'0' && b <= L'9') ? b - L'0' :
                       (b >= L'A' && b <= L'F') ? b - L'A' + 10 :
                       (b >= L'a' && b <= L'f') ? b - L'a' + 10 : -1;
        if (ha < 0 || hb < 0) return false;
        out.push_back(static_cast<uint8_t>((ha << 4) | hb));
    }
    return true;
}

static bool parse_compact_operation(const std::wstring& line, int formatVersion, Operation& op, std::wstring& err) {
    if (line.size() < 3 || line[0] != L'$') return false;

    size_t sep = std::wstring::npos;
    wchar_t sepChar = 0;
    for (size_t i = 1; i < line.size(); ++i) {
        if (line[i] == L'=' || line[i] == L'+' || line[i] == L'-') {
            sep = i;
            sepChar = line[i];
            break;
        }
    }
    if (sep == std::wstring::npos || sep <= 1) {
        err = L"Invalid compact operation.";
        return false;
    }

    const std::wstring offsetText = trimw(line.substr(1, sep - 1));
    for (size_t i = 0; i < offsetText.size(); ++i) {
        const wchar_t c = offsetText[i];
        if (!((c >= L'0' && c <= L'9') || (c >= L'a' && c <= L'f') || (c >= L'A' && c <= L'F'))) {
            err = L"Invalid compact operation offset.";
            return false;
        }
    }

    op = Operation();
    op.hasType = true;
    op.hasOriginal = true;
    op.hasPatched = true;
    if (!parse_u64(L"0x" + offsetText, op.offset)) {
        err = L"Invalid compact operation offset.";
        return false;
    }

    const std::wstring value = line.substr(sep + 1);

    if (sepChar == L'=') {
        // v1: OFFSET=NEW-OLD
        // v2: OFFSET=NEW
        if (value.empty()) {
            err = L"Invalid compact replace operation.";
            return false;
        }

        std::wstring newText = value;
        std::wstring oldText;
        if (formatVersion == 1) {
            const size_t oldSep = value.rfind(L'-');
            if (oldSep == std::wstring::npos || oldSep == 0 || oldSep + 1 >= value.size()) {
                err = L"Invalid format v1 replace operation. Expected OFFSET=NEW-OLD.";
                return false;
            }
            newText = value.substr(0, oldSep);
            oldText = value.substr(oldSep + 1);
        }

        if (!hexbyte_compact(newText, op.patched) || op.patched.empty()) {
            err = L"Invalid compact replacement bytes.";
            return false;
        }

        op.type = L"replace";
        if (formatVersion == 1) {
            if (!hexbyte_compact(oldText, op.original) || op.original.empty()) {
                err = L"Invalid compact original bytes.";
                return false;
            }
            if (op.original.size() != op.patched.size()) {
                err = L"A v1 replace operation must have equal original and new lengths.";
                return false;
            }
        } else {
            op.original.clear();
            op.hasOriginal = false;
            op.lengthOnly = true;
            op.deleteLength = op.patched.size();
        }
        return true;
    }

    if (sepChar == L'+') {
        // Both versions: OFFSET+NEW
        if (!hexbyte_compact(value, op.patched) || op.patched.empty()) {
            err = L"Invalid compact insertion bytes.";
            return false;
        }
        op.type = L"insert";
        op.original.clear();
        return true;
    }

    // v1: OFFSET-OLD
    // v2: OFFSET-LENGTH
    if (value.empty()) {
        err = L"Invalid compact delete operation.";
        return false;
    }

    op.type = L"delete";
    op.patched.clear();

    if (formatVersion == 1) {
        if (!hexbyte_compact(value, op.original) || op.original.empty()) {
            err = L"Invalid compact original bytes.";
            return false;
        }
        return true;
    }

    uint64_t n = 0;
    if (!parse_u64(value, n) || n == 0 || n > static_cast<uint64_t>(SIZE_MAX)) {
        err = L"Invalid compact delete length.";
        return false;
    }
    op.original.clear();
    op.hasOriginal = false;
    op.lengthOnly = true;
    op.deleteLength = static_cast<size_t>(n);
    return true;
}

/* Format version 2 (selected by -b):
   $OFFSET=PATCHED_HEX
   $OFFSET-LENGTH
   $OFFSET+PATCHED_HEX
   The original bytes are deliberately omitted; target_sha256 identifies the
   source file, while application works from the supplied source bytes. */
static bool parse_brute_operation(const std::wstring& line, Operation& op, std::wstring& err) {
    return parse_compact_operation(line, 2, op, err);
}

static bool parse_patch_text(const std::string& raw, Patch& p, std::wstring& err) {
    std::wstring text;
    if (!utf8_to_wide(raw, text)) {
        err = L"The patch must be UTF-8.";
        return false;
    }

    size_t pos = 0;
    Operation current = {};
    bool inOperation = false;

    while (pos < text.size()) {
        size_t end = text.find(L'\n', pos);
        if (end == std::wstring::npos) end = text.size();

        const std::wstring line = trimw(text.substr(pos, end - pos));
        pos = (end == text.size()) ? end : end + 1;

        if (line.empty() || line[0] == L'#' || line[0] == L';') continue;

        const bool isMetadataLine =
            line.rfind(L"format_version=", 0) == 0 ||
            line.rfind(L"name=", 0) == 0 ||
            line.rfind(L"description=", 0) == 0 ||
            line.rfind(L"target_sha256=", 0) == 0 ||
            line.rfind(L"patched_sha256=", 0) == 0 ||
            line.rfind(L"patch_sha256=", 0) == 0;

        if (!isMetadataLine &&
            line.size() >= 3 && line[0] == L'$' &&
            line.find_first_of(L"=+-", 1) != std::wstring::npos &&
            line.find_first_not_of(L"0123456789abcdefABCDEF=+-$\t") == std::wstring::npos) {
            if (inOperation) {
                err = L"Compact and legacy operation formats cannot be mixed inside an operation.";
                return false;
            }
            Operation op = {};
            if (!parse_compact_operation(line, p.formatVersion, op, err)) return false;
            p.ops.push_back(op);
            continue;
        }

        if (line.front() == L'[') {
            if (line == L"[patch]") {
                inOperation = false;
                continue;
            }

            if (line.rfind(L"[op", 0) == 0 && line.back() == L']') {
                if (inOperation) {
                    if (!current.hasType || current.type.empty() ||
                        !current.hasOriginal || !current.hasPatched) {
                        err = L"Incomplete operation: type, original and patched are required.";
                        return false;
                    }
                    if (current.type == L"replace") {
                        if (current.original.empty() || current.patched.empty()) {
                            err = L"A replace operation must contain original and patched.";
                            return false;
                        }
                    } else if (current.type == L"insert") {
                        if (!current.original.empty() || current.patched.empty()) {
                            err = L"An insert operation must have empty original= and non-empty patched.";
                            return false;
                        }
                    } else if (current.type == L"delete") {
                        if (current.original.empty() || !current.patched.empty()) {
                            err = L"A delete operation must have non-empty original and empty patched= .";
                            return false;
                        }
                    } else {
                        err = L"Unknown operation type: " + current.type;
                        return false;
                    }
                    p.ops.push_back(current);
                }
                current = Operation();
                inOperation = true;
                continue;
            }

            err = L"Unknown section in patch.";
            return false;
        }

        const size_t eq = line.find(L'=');
        if (eq == std::wstring::npos) {
            err = L"Invalid line in patch.";
            return false;
        }

        const std::wstring key = trimw(line.substr(0, eq));
        const std::wstring value = trimw(line.substr(eq + 1));

        if (!inOperation) {
            if (key == L"format_version") {
                uint64_t version = 0;
                if (!parse_u64(value, version) || version > 0x7fffffffULL) {
                    err = L"Invalid format_version.";
                    return false;
                }
                p.formatVersion = static_cast<int>(version);
            } else if (key == L"name") {
                p.name = value;
            } else if (key == L"description") {
                p.description = value;
            } else if (key == L"target_sha256") {
                std::string utf8;
                if (!wide_to_utf8(value, utf8)) { err = L"Invalid target_sha256 hash."; return false; }
                p.targetSha = lowerascii(utf8);
            } else if (key == L"patched_sha256") {
                std::string utf8;
                if (!wide_to_utf8(value, utf8)) { err = L"Invalid patched_sha256 hash."; return false; }
                p.patchedSha = lowerascii(utf8);
            } else if (key == L"patch_sha256") {
                std::string utf8;
                if (!wide_to_utf8(value, utf8)) { err = L"Invalid patch_sha256 hash."; return false; }
                p.patchSha = lowerascii(utf8);
            }
        } else {
            if (key == L"type") {
                current.type = value;
                for (size_t i = 0; i < current.type.size(); ++i) {
                    if (current.type[i] >= L'A' && current.type[i] <= L'Z')
                        current.type[i] = static_cast<wchar_t>(current.type[i] - L'A' + L'a');
                }
                current.hasType = true;
            } else if (key == L"offset") {
                if (!parse_u64(value, current.offset)) { err = L"Invalid offset."; return false; }
            } else if (key == L"original") {
                current.hasOriginal = true;
                if (!hexbyte(value, current.original)) { err = L"Invalid original bytes."; return false; }
            } else if (key == L"patched") {
                current.hasPatched = true;
                if (!hexbyte(value, current.patched)) { err = L"Invalid patched bytes."; return false; }
            }
        }
    }

    if (inOperation) {
        if (!current.hasType || current.type.empty() || !current.hasOriginal || !current.hasPatched) {
            err = L"Last operation is incomplete: type, original and patched are required.";
            return false;
        }
        if (current.type == L"replace") {
            if (current.original.empty() || current.patched.empty()) { err = L"A replace operation must contain original and patched."; return false; }
        } else if (current.type == L"insert") {
            if (!current.original.empty() || current.patched.empty()) { err = L"An insert operation must have empty original= and non-empty patched."; return false; }
        } else if (current.type == L"delete") {
            if (current.original.empty() || !current.patched.empty()) { err = L"A delete operation must have non-empty original and empty patched= ."; return false; }
        } else {
            err = L"Unknown operation type: " + current.type;
            return false;
        }
        p.ops.push_back(current);
    }

    if (p.formatVersion != 1 && p.formatVersion != 2) {
        err = L"Unsupported or missing patch format_version (expected 1 or 2).";
        return false;
    }
    if (p.targetSha.size() != 64 || p.patchedSha.size() != 64 || p.patchSha.size() != 64 || p.ops.empty()) {
        err = L"Incomplete patch: missing hashes or operations.";
        return false;
    }
    return true;
}


static bool patch_bytes(std::vector<uint8_t>& data, const Patch& p, std::wstring& err) {
    // Offsets are defined against the original file. Work backwards so that
    // insertions/deletions do not alter the offsets of earlier operations.
    for (size_t i = 0; i < p.ops.size(); ++i) {
        const Operation& op = p.ops[i];
        const size_t requiredOld = (op.type == L"delete" && op.lengthOnly) ? op.deleteLength :
                                    ((op.type == L"replace" && op.lengthOnly) ? op.deleteLength : op.original.size());
        if (op.offset > static_cast<uint64_t>(data.size()) ||
            requiredOld > data.size() - static_cast<size_t>(op.offset)) {
            err = L"Operation " + std::to_wstring(i + 1) + L" is outside the file.";
            return false;
        }

        if (!op.lengthOnly && !op.original.empty() &&
            memcmp(&data[static_cast<size_t>(op.offset)],
                   op.original.data(), op.original.size()) != 0) {
            err = L"Content at offset " + std::to_wstring(op.offset) +
                  L" does not match original.";
            return false;
        }
    }

    for (size_t n = p.ops.size(); n > 0; --n) {
        const Operation& op = p.ops[n - 1];
        const size_t pos = static_cast<size_t>(op.offset);
        const size_t oldSize = op.lengthOnly ? op.deleteLength : op.original.size();

        if (op.type == L"replace") {
            data.erase(data.begin() + pos, data.begin() + pos + oldSize);
            data.insert(data.begin() + pos, op.patched.begin(), op.patched.end());
        } else if (op.type == L"insert") {
            data.insert(data.begin() + pos, op.patched.begin(), op.patched.end());
        } else if (op.type == L"delete") {
            data.erase(data.begin() + pos, data.begin() + pos + oldSize);
        } else {
            err = L"Unknown operation type: " + op.type;
            return false;
        }
    }

    return true;
}


static bool save_atomic(const std::wstring& path, const std::vector<uint8_t>& data, std::wstring& err) {
    const std::wstring temp = path + L".patching.tmp";
    HANDLE handle = CreateFileW(temp.c_str(), GENERIC_WRITE, 0, NULL, CREATE_ALWAYS,
                                FILE_ATTRIBUTE_NORMAL, NULL);
    if (handle == INVALID_HANDLE_VALUE) {
        err = L"Unable to create temporary file.";
        return false;
    }

    size_t pos = 0;
    while (pos < data.size()) {
        const size_t remaining = data.size() - pos;
        const DWORD chunk = static_cast<DWORD>(remaining > (1u << 20) ? (1u << 20) : remaining);
        DWORD written = 0;

        if (!WriteFile(handle, &data[pos], chunk, &written, NULL) || written != chunk) {
            CloseHandle(handle);
            DeleteFileW(temp.c_str());
            err = L"Write error.";
            return false;
        }
        pos += written;
    }

    FlushFileBuffers(handle);
    CloseHandle(handle);

    if (!ReplaceFileW(path.c_str(), temp.c_str(), NULL, REPLACEFILE_IGNORE_MERGE_ERRORS, NULL, NULL)) {
        if (!MoveFileExW(temp.c_str(), path.c_str(), MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
            DeleteFileW(temp.c_str());
            err = L"Unable to replace the original file.";
            return false;
        }
    }

    return true;
}


struct ProfileTimer {
    const char* name;
    std::chrono::steady_clock::time_point start;

    explicit ProfileTimer(const char* n)
        : name(n), start(std::chrono::steady_clock::now()) {}

    void report() const {
        const double seconds = std::chrono::duration<double>(
            std::chrono::steady_clock::now() - start).count();
		if (g_debug) {
			std::cerr << "[DEBUG] " << name << " : "
					  << std::fixed << std::setprecision(3)
					  << seconds << " s\n";
		}
    }

    void reset(const char* n) {
        name = n;
        start = std::chrono::steady_clock::now();
    }
};

static unsigned int get_worker_count() {
    const unsigned int hw = std::thread::hardware_concurrency();
    return hw == 0 ? 1 : hw;
}


template <typename FingerprintT>
static void radix_sort_fingerprints(std::vector<FingerprintT>& v)
{
    if (v.size() < 2)
        return;

    std::vector<FingerprintT> tmp(v.size());

    // Stable LSD radix sort.
    // First sort by pos, then by hash, so the final order is:
    // hash ascending, then pos ascending.
    std::vector<FingerprintT>* srcVec = &v;
    std::vector<FingerprintT>* dstVec = &tmp;

    auto pass_pos = [](std::vector<FingerprintT>& in,
                       std::vector<FingerprintT>& out,
                       unsigned shift)
    {
        size_t count[256] = {};

        for (size_t i = 0; i < in.size(); ++i) {
            const uint64_t key = static_cast<uint64_t>(in[i].pos);
            ++count[(key >> shift) & 0xFFu];
        }

        size_t offset[256];
        offset[0] = 0;
        for (size_t i = 1; i < 256; ++i)
            offset[i] = offset[i - 1] + count[i - 1];

        for (size_t i = 0; i < in.size(); ++i) {
            const uint64_t key = static_cast<uint64_t>(in[i].pos);
            out[offset[(key >> shift) & 0xFFu]++] = in[i];
        }
    };

    auto pass_hash = [](std::vector<FingerprintT>& in,
                        std::vector<FingerprintT>& out,
                        unsigned shift)
    {
        size_t count[256] = {};

        for (size_t i = 0; i < in.size(); ++i) {
            const uint64_t key = in[i].hash;
            ++count[(key >> shift) & 0xFFu];
        }

        size_t offset[256];
        offset[0] = 0;
        for (size_t i = 1; i < 256; ++i)
            offset[i] = offset[i - 1] + count[i - 1];

        for (size_t i = 0; i < in.size(); ++i) {
            const uint64_t key = in[i].hash;
            out[offset[(key >> shift) & 0xFFu]++] = in[i];
        }
    };

    for (unsigned shift = 0; shift < sizeof(size_t) * 8; shift += 8) {
        pass_pos(*srcVec, *dstVec, shift);
        std::swap(srcVec, dstVec);
    }

    for (unsigned shift = 0; shift < 64; shift += 8) {
        pass_hash(*srcVec, *dstVec, shift);
        std::swap(srcVec, dstVec);
    }

    if (srcVec != &v)
        v.swap(*srcVec);
}

static int generate_patch(const wchar_t* originalPath, const wchar_t* patchedPath, const std::wstring& outputPath, const std::wstring& patchName, const std::wstring& patchDescription, bool compressOutput, bool bruteMode) {
    print_wline(PATCHER_NAME L" - patch generation...");
    // std::cerr << "[DEBUG] hardware threads : " << get_worker_count() << "\n";
    print_wline(std::wstring(L"  Original : ") + originalPath);
    print_wline(std::wstring(L"  Patched  : ") + patchedPath);

    std::vector<uint8_t> original;
    std::vector<uint8_t> patched;

    std::chrono::steady_clock::time_point debugStageStart =
        std::chrono::steady_clock::now();

    if (!read_all(originalPath, original)) {
        std::wcerr << L"Error: unable to read the original file.\n";
        return 3;
    }
    debug_report("read original", debugStageStart);
    debugStageStart = std::chrono::steady_clock::now();

    if (!read_all(patchedPath, patched)) {
        std::wcerr << L"Error: unable to read the patched file.\n";
        return 4;
    }
    debug_report("read patched", debugStageStart);

    print_wline(std::wstring(L"  Original size   : ") + std::to_wstring(original.size()) + L" bytes");
    print_wline(std::wstring(L"  Patched size    : ") + std::to_wstring(patched.size()) + L" bytes");

    ProfileTimer profileGeneration("SHA + diff generation");

    if (original == patched) {
        std::wcerr << L"Error: original and patched files are identical; no patch is needed.\n";
        return 5;
    }

    struct Diff {
        std::string type;
        size_t offset;
        size_t originalBegin;
        size_t originalEnd;
        size_t patchedBegin;
        size_t patchedEnd;
    };

    std::vector<Diff> diffs;

    /*
       Conservative binary diff generation.

       We intentionally do NOT pick an arbitrary repeated block as an anchor.
       Instead we:
         1. hash fixed-size blocks in both files;
         2. keep only hashes occurring exactly once in each file;
         3. turn those unique matches into (originalPos, patchedPos) pairs;
         4. compute a longest-increasing-subsequence on patchedPos.

       The LIS preserves the order of the matched blocks and prevents the
       generator from jumping between repeated regions. This is substantially
       safer for DLLs containing repeated code/data/padding than selecting the
       globally longest local match.
    */
    const size_t BLOCK = 32;
    const size_t STRIDE = 4;
    const size_t MIN_MATCH = 32;

    struct Fingerprint {
        uint64_t hash;
        size_t pos;
    };

    struct Match {
        size_t o;
        size_t p;
    };

    auto hash_block = [](const std::vector<uint8_t>& data, size_t pos, size_t len) -> uint64_t {
        uint64_t h = 1469598103934665603ULL;
        for (size_t i = 0; i < len; ++i) {
            h ^= data[pos + i];
            h *= 1099511628211ULL;
        }
        return h;
    };

    const size_t N = original.size();
    const size_t M = patched.size();

    ProfileTimer profileFingerprints("global fingerprints");
    std::vector<Fingerprint> originalFp;
    std::vector<Fingerprint> patchedFp;

    const unsigned int workers = get_worker_count();

    auto build_fingerprints = [&](const std::vector<uint8_t>& data,
                                   size_t beginPos,
                                   size_t endPos,
                                   std::vector<Fingerprint>& out) {
        if (endPos <= beginPos || endPos - beginPos < BLOCK) return;

        const size_t count = ((endPos - beginPos - BLOCK) / STRIDE) + 1;
        const unsigned int threadCount =
            (std::min)(workers, static_cast<unsigned int>((count + 65535) / 65536));

        if (threadCount <= 1) {
            out.reserve(count);
            for (size_t i = 0; i < count; ++i) {
                const size_t pos = beginPos + i * STRIDE;
                out.push_back({ hash_block(data, pos, BLOCK), pos });
            }
            return;
        }

        std::vector<std::vector<Fingerprint> > parts(threadCount);
        std::vector<std::thread> threads;
        threads.reserve(threadCount);

        for (unsigned int t = 0; t < threadCount; ++t) {
            const size_t first = (count * t) / threadCount;
            const size_t last = (count * (t + 1)) / threadCount;

            threads.push_back(std::thread([&, t, first, last]() {
                std::vector<Fingerprint>& part = parts[t];
                part.reserve(last - first);

                for (size_t i = first; i < last; ++i) {
                    const size_t pos = beginPos + i * STRIDE;
                    part.push_back({ hash_block(data, pos, BLOCK), pos });
                }
            }));
        }

        for (size_t i = 0; i < threads.size(); ++i)
            threads[i].join();

        out.reserve(count);
        for (unsigned int t = 0; t < threadCount; ++t) {
            out.insert(out.end(), parts[t].begin(), parts[t].end());
        }
    };

    if (N >= BLOCK)
        build_fingerprints(original, 0, N, originalFp);

    if (M >= BLOCK)
        build_fingerprints(patched, 0, M, patchedFp);

    profileFingerprints.report();
    ProfileTimer profileFine("sort original fingerprints");
    radix_sort_fingerprints(originalFp);

    profileFine.report();
    profileFine.reset("sort patched fingerprints");
    radix_sort_fingerprints(patchedFp);

    profileFine.report();
    profileFine.reset("merge unique matches");

    // Both arrays are sorted by (hash, pos). Merge them directly.
    // Store the matching patched position by original block index so that
    // the final scan can emit uniqueMatches in original-offset order.
    const size_t originalBlockCount =
        (N >= BLOCK) ? ((N - BLOCK) / STRIDE + 1) : 0;

    const size_t NO_MATCH = static_cast<size_t>(-1);
    std::vector<size_t> matchPos(originalBlockCount, NO_MATCH);

    size_t oi = 0;
    size_t pi = 0;

    while (oi < originalFp.size() && pi < patchedFp.size()) {
        const uint64_t oh = originalFp[oi].hash;
        const uint64_t ph = patchedFp[pi].hash;

        if (oh < ph) {
            size_t oj = oi + 1;
            while (oj < originalFp.size() &&
                   originalFp[oj].hash == oh) {
                ++oj;
            }
            oi = oj;
            continue;
        }

        if (ph < oh) {
            size_t pj = pi + 1;
            while (pj < patchedFp.size() &&
                   patchedFp[pj].hash == ph) {
                ++pj;
            }
            pi = pj;
            continue;
        }

        size_t oj = oi + 1;
        while (oj < originalFp.size() &&
               originalFp[oj].hash == oh) {
            ++oj;
        }

        size_t pj = pi + 1;
        while (pj < patchedFp.size() &&
               patchedFp[pj].hash == ph) {
            ++pj;
        }

        // Only hashes unique on both sides are valid candidates.
        if (oj - oi == 1 && pj - pi == 1) {
            const size_t o = originalFp[oi].pos;
            const size_t pp = patchedFp[pi].pos;

            if (std::memcmp(&original[o], &patched[pp], BLOCK) == 0)
                matchPos[o / STRIDE] = pp;
        }

        oi = oj;
        pi = pj;
    }

    std::vector<Match> uniqueMatches;
    uniqueMatches.reserve((std::min)(originalFp.size(), patchedFp.size()));

    // Emit in original-offset order, preserving the exact order previously
    // obtained from uniqueOriginal + flat hash.
    for (size_t o = 0; o + BLOCK <= N; o += STRIDE) {
        const size_t pp = matchPos[o / STRIDE];
        if (pp != NO_MATCH)
            uniqueMatches.push_back({ o, pp });
    }

    profileFine.report();
    profileFine.reset("LIS");

    /*
       Longest increasing subsequence of patched positions. Every selected
       anchor therefore moves forward in both files.
    */
    std::vector<size_t> tails;
    std::vector<size_t> prev(uniqueMatches.size(), static_cast<size_t>(-1));
    tails.reserve(uniqueMatches.size());

    for (size_t i = 0; i < uniqueMatches.size(); ++i) {
        const size_t p = uniqueMatches[i].p;
        std::vector<size_t>::iterator it = std::lower_bound(
            tails.begin(), tails.end(), p,
            [&](size_t index, size_t value) {
                return uniqueMatches[index].p < value;
            });

        const size_t pos = static_cast<size_t>(it - tails.begin());
        if (pos > 0) prev[i] = tails[pos - 1];

        if (it == tails.end()) tails.push_back(i);
        else *it = i;
    }

    profileFine.report();
    profileFine.reset("reconstruct anchors");

    std::vector<Match> anchors;
    if (!tails.empty()) {
        size_t index = tails.back();
        while (index != static_cast<size_t>(-1)) {
            anchors.push_back(uniqueMatches[index]);
            index = prev[index];
        }
        std::reverse(anchors.begin(), anchors.end());
    }

    profileFine.report();
    profileFine.reset("emit regions + local anchors");



    auto add_diff = [&](const std::string& type, size_t oBegin, size_t oEnd, size_t pBegin, size_t pEnd) {
        if (oBegin == oEnd && pBegin == pEnd) return;
        Diff d;
        d.type = type;
        d.offset = oBegin;
        d.originalBegin = oBegin;
        d.originalEnd = oEnd;
        d.patchedBegin = pBegin;
        d.patchedEnd = pEnd;
        diffs.push_back(d);
    };

    std::function<void(size_t, size_t, size_t, size_t)> emit_region;
    emit_region = [&](size_t oBegin, size_t oEnd, size_t pBegin, size_t pEnd) {
        while (oBegin < oEnd && pBegin < pEnd && original[oBegin] == patched[pBegin]) {
            ++oBegin; ++pBegin;
        }
        while (oBegin < oEnd && pBegin < pEnd &&
               original[oEnd - 1] == patched[pEnd - 1]) {
            --oEnd; --pEnd;
        }
        if (oBegin == oEnd && pBegin == pEnd) return;
        if (oBegin == oEnd) {
            add_diff("insert", oBegin, oBegin, pBegin, pEnd);
            return;
        }
        if (pBegin == pEnd) {
            add_diff("delete", oBegin, oEnd, pBegin, pBegin);
            return;
        }

        /*
           Unequal regions need local anchors so that an insertion/deletion
           inside an otherwise matching area is not misclassified as a
           replace.  The global 32-byte anchors remain the primary mechanism;
           this local pass is only used inside a gap that survived them.
           We use unique 8-byte matches with a 1-byte scan and an LIS.
        */
        // Local anchor construction is intentionally bounded.
        // A huge gap must never allocate one fingerprint per byte.
        const size_t MAX_LOCAL_ANCHOR_REGION = 8 * 1024 * 1024; // 8 MiB per side
        if (oEnd - oBegin <= MAX_LOCAL_ANCHOR_REGION &&
            pEnd - pBegin <= MAX_LOCAL_ANCHOR_REGION &&
            oEnd - oBegin >= 8 && pEnd - pBegin >= 8) {
            const size_t L = 8;
            const size_t S = 1;
            struct LocalFp { uint64_t hash; size_t pos; };
            std::vector<LocalFp> ofp, pfp;

            auto build_local = [&](const std::vector<uint8_t>& data,
                                   size_t beginPos, size_t endPos,
                                   std::vector<LocalFp>& out) {
                const size_t count = endPos - beginPos - L + 1;
                const unsigned int tc =
                    (std::min)(workers, static_cast<unsigned int>((count + 65535) / 65536));

                if (tc <= 1) {
                    out.reserve(count);
                    for (size_t i = 0; i < count; ++i) {
                        const size_t pos = beginPos + i * S;
                        out.push_back({ hash_block(data, pos, L), pos });
                    }
                    return;
                }

                std::vector<std::vector<LocalFp> > parts(tc);
                std::vector<std::thread> ts;
                ts.reserve(tc);

                for (unsigned int t = 0; t < tc; ++t) {
                    const size_t first = (count * t) / tc;
                    const size_t last = (count * (t + 1)) / tc;
                    ts.push_back(std::thread([&, t, first, last]() {
                        std::vector<LocalFp>& part = parts[t];
                        part.reserve(last - first);
                        for (size_t i = first; i < last; ++i) {
                            const size_t pos = beginPos + i * S;
                            part.push_back({ hash_block(data, pos, L), pos });
                        }
                    }));
                }

                for (size_t i = 0; i < ts.size(); ++i) ts[i].join();

                out.reserve(count);
                for (unsigned int t = 0; t < tc; ++t)
                    out.insert(out.end(), parts[t].begin(), parts[t].end());
            };

            build_local(original, oBegin, oEnd, ofp);
            build_local(patched, pBegin, pEnd, pfp);

            std::sort(ofp.begin(), ofp.end(), [](const LocalFp& a, const LocalFp& b) {
                if (a.hash != b.hash) return a.hash < b.hash;
                return a.pos < b.pos;
            });
            std::sort(pfp.begin(), pfp.end(), [](const LocalFp& a, const LocalFp& b) {
                if (a.hash != b.hash) return a.hash < b.hash;
                return a.pos < b.pos;
            });

            std::unordered_map<uint64_t, size_t> pu;
            pu.reserve(pfp.size() * 2 + 1);
            for (size_t i = 0; i < pfp.size();) {
                size_t j = i + 1;
                while (j < pfp.size() && pfp[j].hash == pfp[i].hash) ++j;
                if (j - i == 1) pu[pfp[i].hash] = pfp[i].pos;
                i = j;
            }

            std::vector<Match> lm;
            for (size_t i = 0; i < ofp.size();) {
                size_t j = i + 1;
                while (j < ofp.size() && ofp[j].hash == ofp[i].hash) ++j;
                if (j - i == 1) {
                    std::unordered_map<uint64_t, size_t>::const_iterator it = pu.find(ofp[i].hash);
                    if (it != pu.end() && std::memcmp(&original[ofp[i].pos], &patched[it->second], L) == 0)
                        lm.push_back({ ofp[i].pos, it->second });
                }
                i = j;
            }
            std::sort(lm.begin(), lm.end(), [](const Match& a, const Match& b) {
                if (a.o != b.o) return a.o < b.o;
                return a.p < b.p;
            });

            std::vector<size_t> tails2;
            std::vector<size_t> prev2(lm.size(), static_cast<size_t>(-1));
            for (size_t i = 0; i < lm.size(); ++i) {
                std::vector<size_t>::iterator it = std::lower_bound(
                    tails2.begin(), tails2.end(), lm[i].p,
                    [&](size_t index, size_t value) { return lm[index].p < value; });
                const size_t k = static_cast<size_t>(it - tails2.begin());
                if (k > 0) prev2[i] = tails2[k - 1];
                if (it == tails2.end()) tails2.push_back(i); else *it = i;
            }

            std::vector<Match> localAnchors;
            if (!tails2.empty()) {
                size_t idx = tails2.back();
                while (idx != static_cast<size_t>(-1)) {
                    localAnchors.push_back(lm[idx]);
                    idx = prev2[idx];
                }
                std::reverse(localAnchors.begin(), localAnchors.end());
            }

            if (!localAnchors.empty()) {
                size_t co = oBegin, cp = pBegin;
                bool usedAnchor = false;
                for (size_t i = 0; i < localAnchors.size(); ++i) {
                    const Match& a = localAnchors[i];
                    if (a.o < co || a.p < cp) continue;

                    // The anchor itself is known to be identical. Everything
                    // before it is therefore a separate edit region.
                    if (a.o > co || a.p > cp) {
                        emit_region(co, a.o, cp, a.p);
                    }
                    co = a.o + L;
                    cp = a.p + L;
                    usedAnchor = true;
                }
                if (co < oEnd || cp < pEnd) {
                    emit_region(co, oEnd, cp, pEnd);
                }
                if (usedAnchor) return;
            }
        }

        /* If 8-byte anchors are insufficient, try unique 4-byte anchors.
           This is deliberately a fallback: it is used only for an unequal
           region where the stronger 8-byte pass found nothing. Its purpose is
           to expose short common runs around insertions/deletions instead of
           collapsing the whole unequal region into replace/delete pairs. */
        if (oEnd - oBegin <= MAX_LOCAL_ANCHOR_REGION &&
            pEnd - pBegin <= MAX_LOCAL_ANCHOR_REGION &&
            oEnd - oBegin >= 4 && pEnd - pBegin >= 4) {
            const size_t L = 4;
            const size_t S = 1;
            struct TinyFp { uint64_t hash; size_t pos; };
            std::vector<TinyFp> ofp, pfp;

            auto build_tiny = [&](const std::vector<uint8_t>& data,
                                  size_t beginPos, size_t endPos,
                                  std::vector<TinyFp>& out) {
                const size_t count = endPos - beginPos - L + 1;
                const unsigned int tc =
                    (std::min)(workers, static_cast<unsigned int>((count + 65535) / 65536));

                if (tc <= 1) {
                    out.reserve(count);
                    for (size_t i = 0; i < count; ++i) {
                        const size_t pos = beginPos + i * S;
                        out.push_back({ hash_block(data, pos, L), pos });
                    }
                    return;
                }

                std::vector<std::vector<TinyFp> > parts(tc);
                std::vector<std::thread> ts;
                ts.reserve(tc);

                for (unsigned int t = 0; t < tc; ++t) {
                    const size_t first = (count * t) / tc;
                    const size_t last = (count * (t + 1)) / tc;
                    ts.push_back(std::thread([&, t, first, last]() {
                        std::vector<TinyFp>& part = parts[t];
                        part.reserve(last - first);
                        for (size_t i = first; i < last; ++i) {
                            const size_t pos = beginPos + i * S;
                            part.push_back({ hash_block(data, pos, L), pos });
                        }
                    }));
                }

                for (size_t i = 0; i < ts.size(); ++i) ts[i].join();

                out.reserve(count);
                for (unsigned int t = 0; t < tc; ++t)
                    out.insert(out.end(), parts[t].begin(), parts[t].end());
            };

            build_tiny(original, oBegin, oEnd, ofp);
            build_tiny(patched, pBegin, pEnd, pfp);

            std::sort(ofp.begin(), ofp.end(), [](const TinyFp& a, const TinyFp& b) {
                if (a.hash != b.hash) return a.hash < b.hash;
                return a.pos < b.pos;
            });
            std::sort(pfp.begin(), pfp.end(), [](const TinyFp& a, const TinyFp& b) {
                if (a.hash != b.hash) return a.hash < b.hash;
                return a.pos < b.pos;
            });

            std::unordered_map<uint64_t, size_t> pu4;
            pu4.reserve(pfp.size() * 2 + 1);
            for (size_t i = 0; i < pfp.size();) {
                size_t j = i + 1;
                while (j < pfp.size() && pfp[j].hash == pfp[i].hash) ++j;
                if (j - i == 1) pu4[pfp[i].hash] = pfp[i].pos;
                i = j;
            }

            std::vector<Match> lm4;
            for (size_t i = 0; i < ofp.size();) {
                size_t j = i + 1;
                while (j < ofp.size() && ofp[j].hash == ofp[i].hash) ++j;
                if (j - i == 1) {
                    std::unordered_map<uint64_t, size_t>::const_iterator it = pu4.find(ofp[i].hash);
                    if (it != pu4.end() && std::memcmp(&original[ofp[i].pos], &patched[it->second], L) == 0)
                        lm4.push_back({ ofp[i].pos, it->second });
                }
                i = j;
            }
            std::sort(lm4.begin(), lm4.end(), [](const Match& a, const Match& b) {
                if (a.o != b.o) return a.o < b.o;
                return a.p < b.p;
            });

            std::vector<size_t> tails4;
            std::vector<size_t> prev4(lm4.size(), static_cast<size_t>(-1));
            for (size_t i = 0; i < lm4.size(); ++i) {
                std::vector<size_t>::iterator it = std::lower_bound(
                    tails4.begin(), tails4.end(), lm4[i].p,
                    [&](size_t index, size_t value) { return lm4[index].p < value; });
                const size_t k = static_cast<size_t>(it - tails4.begin());
                if (k > 0) prev4[i] = tails4[k - 1];
                if (it == tails4.end()) tails4.push_back(i); else *it = i;
            }

            std::vector<Match> anchors4;
            if (!tails4.empty()) {
                size_t idx = tails4.back();
                while (idx != static_cast<size_t>(-1)) {
                    anchors4.push_back(lm4[idx]);
                    idx = prev4[idx];
                }
                std::reverse(anchors4.begin(), anchors4.end());
            }

            if (!anchors4.empty()) {
                size_t co = oBegin, cp = pBegin;
                bool usedAnchor = false;
                for (size_t i = 0; i < anchors4.size(); ++i) {
                    const Match& a = anchors4[i];
                    if (a.o < co || a.p < cp) continue;
                    if (a.o > co || a.p > cp) emit_region(co, a.o, cp, a.p);
                    co = a.o + L;
                    cp = a.p + L;
                    usedAnchor = true;
                }
                if (co < oEnd || cp < pEnd) emit_region(co, oEnd, cp, pEnd);
                if (usedAnchor) return;
            }
        }

        /* No sufficiently long local anchor was found. Never emit an unequal
           replace: the compact r@ syntax represents equal-length replacement
           data only. Trim any byte-wise common edges, then represent the
           remaining unequal middle as an equal-length replace plus an insert
           or delete. This keeps the operation semantics unambiguous. */
        while (oBegin < oEnd && pBegin < pEnd && original[oBegin] == patched[pBegin]) {
            ++oBegin;
            ++pBegin;
        }
        while (oBegin < oEnd && pBegin < pEnd &&
               original[oEnd - 1] == patched[pEnd - 1]) {
            --oEnd;
            --pEnd;
        }

        if (oBegin == oEnd && pBegin == pEnd) return;
        if (oBegin == oEnd) {
            add_diff("insert", oBegin, oBegin, pBegin, pEnd);
            return;
        }
        if (pBegin == pEnd) {
            add_diff("delete", oBegin, oEnd, pBegin, pBegin);
            return;
        }

        const size_t commonLen = (std::min)(oEnd - oBegin, pEnd - pBegin);
        if (commonLen > 0) {
            add_diff("replace", oBegin, oBegin + commonLen,
                     pBegin, pBegin + commonLen);
            oBegin += commonLen;
            pBegin += commonLen;
        }
        if (oBegin < oEnd) add_diff("delete", oBegin, oEnd, pBegin, pBegin);
        if (pBegin < pEnd) add_diff("insert", oBegin, oBegin, pBegin, pEnd);
    };

    size_t cursorO = 0;
    size_t cursorP = 0;

    for (size_t i = 0; i < anchors.size(); ++i) {
        const Match& a = anchors[i];
        if (a.o < cursorO || a.p < cursorP) continue;
        if (a.o + BLOCK > N || a.p + BLOCK > M) continue;

        size_t common = BLOCK;
        const size_t nextO = (i + 1 < anchors.size()) ? anchors[i + 1].o : N;
        const size_t nextP = (i + 1 < anchors.size()) ? anchors[i + 1].p : M;
        while (a.o + common < N && a.p + common < M &&
               a.o + common < nextO && a.p + common < nextP &&
               original[a.o + common] == patched[a.p + common]) ++common;
        if (common < MIN_MATCH) continue;

        emit_region(cursorO, a.o, cursorP, a.p);
        cursorO = a.o + common;
        cursorP = a.p + common;
    }
    emit_region(cursorO, N, cursorP, M);

    if (diffs.empty()) {
        std::wcerr << L"Error: no binary differences were generated.\n";
        return 6;
    }

    /*
       Compact operation optimizer.

       The operation syntax is deliberately small:
         $OFFSET=NEW-OLD\n
       The fixed syntax cost is 5 bytes plus the hexadecimal offset. Bytes are
       emitted without spaces. For replace regions of equal length, operations
       start at a real difference and are considered in 8/16/32-byte windows.
       A window ending in one or more 4-byte equal groups is reduced by those
       groups. If the current window has no removable 4-byte equal tail, the
       next larger window is considered. Dynamic programming uses the actual
       compact text length, including the fixed 5-byte operation syntax, so an
       extra operation is created only when the complete patch becomes smaller.
       Insert/delete regions remain intact.
    */
    auto compact_line_size = [](char type, size_t offset, size_t originalSize, size_t patchedSize) -> size_t {
        (void)type;
        size_t digits = 1;
        size_t v = offset;
        while (v >= 16) { v >>= 4; ++digits; }

        // Generated syntax:
        //   $OFFSET=NEW-OLD\n   (v1 replace)
        //   $OFFSET=NEW\n      (v2 replace)
        //   $OFFSET+NEW\n      (insert)
        //   $OFFSET-OLD\n      (v1 delete)
        //   $OFFSET-LENGTH\n   (v2 delete)
        //
        // This helper is used for replacement optimization only.
        // '$' + offset + '=' + '-' + newline = digits + 4.
        return digits + 4 + (originalSize * 2) + (patchedSize * 2);
    };

    auto optimize_replace_region = [&](const Diff& region, std::vector<Diff>& out) {
        const size_t beginO = region.originalBegin;
        const size_t endO = region.originalEnd;
        const size_t beginP = region.patchedBegin;
        const size_t endP = region.patchedEnd;
        if (endO - beginO != endP - beginP) {
            out.push_back(region);
            return;
        }

        const size_t len = endO - beginO;
        if (len == 0) return;

		/*
		   Memory guard:
		   The exact DP below uses four size_t arrays proportional to the
		   replace-region length. That is unsafe for large binaries.
		   For large regions use a bounded greedy pass instead. It preserves
		   the compact operation format and never allocates O(region_size) memory.
		*/

		const size_t MAX_DP_REGION = 1024 * 1024; // 1 MiB

        if (len > MAX_DP_REGION) {
            size_t s = 0;
            while (s < len) {
                while (s < len && original[beginO + s] == patched[beginP + s]) ++s;
                if (s >= len) break;

                size_t bestEnd = (std::min)(len, s + static_cast<size_t>(8));
                size_t bestCost = compact_line_size('r', beginO + s,
                                                     bestEnd - s, bestEnd - s);

                for (size_t wi = 1; wi < 3; ++wi) {
                    const size_t w = (wi == 1) ? 16 : 32;
                    size_t e = (std::min)(len, s + w);
                    while (e >= s + 4) {
                        bool same4 = true;
                        for (size_t q = 0; q < 4; ++q) {
                            if (original[beginO + e - 4 + q] !=
                                patched[beginP + e - 4 + q]) {
                                same4 = false;
                                break;
                            }
                        }
                        if (!same4) break;
                        e -= 4;
                    }
                    if (e <= s) continue;

                    // Keep the complete selected window in this operation.
                    const size_t cost = compact_line_size('r', beginO + s,
                                                          e - s, e - s);
                    if (cost < bestCost) {
                        bestCost = cost;
                        bestEnd = e;
                    }
                }

                Diff d;
                d.type = "replace";
                d.offset = beginO + s;
                d.originalBegin = beginO + s;
                d.originalEnd = beginO + bestEnd;
                d.patchedBegin = beginP + s;
                d.patchedEnd = beginP + bestEnd;
                out.push_back(d);
                s = bestEnd;
            }
            return;
        }

        // The incoming region already starts at a real difference and ends at
        // the last real difference. Work on that exact interval.
        std::vector<size_t> nextDiff(len + 1, len);
        size_t next = len;
        for (size_t i = len; i > 0; --i) {
            const size_t j = i - 1;
            if (original[beginO + j] != patched[beginP + j]) next = j;
            nextDiff[j] = next;
        }

        const size_t INF = static_cast<size_t>(-1) / 4;
        std::vector<size_t> dp(len + 1, INF);
        std::vector<size_t> choiceEnd(len + 1, len);
        std::vector<size_t> choiceNext(len + 1, len);
        dp[len] = 0;

        const size_t windows[] = { 8, 16, 32 };

        for (size_t s = len; s-- > 0;) {
            if (original[beginO + s] == patched[beginP + s]) continue;

            for (size_t wi = 0; wi < 3; ++wi) {
                const size_t window = windows[wi];
                size_t rawEnd = (std::min)(len, s + window);
                if (rawEnd <= s) continue;

                // A/B/C: if the current window ends in a 4-byte equal group,
                // remove that group, and continue removing equal 4-byte groups
                // immediately before it. Otherwise this window grows to the
                // next size (8 -> 16 -> 32).
                size_t e = rawEnd;
                bool removedEqualTail = false;
                while (e >= s + 4) {
                    bool same4 = true;
                    for (size_t q = 0; q < 4; ++q) {
                        if (original[beginO + e - 4 + q] != patched[beginP + e - 4 + q]) {
                            same4 = false;
                            break;
                        }
                    }
                    if (!same4) break;
                    e -= 4;
                    removedEqualTail = true;
                }

                // If this is not the last available window and nothing was
                // removable at its end, move to the next larger window.
                if (!removedEqualTail && rawEnd < len && wi < 2) continue;
                if (e <= s) continue;

                // Keep every real difference covered by this window in the
                // same replace operation. Only the equal suffix is removed.
                const size_t nd = nextDiff[e];
                if (nd != len && nd < e) continue;

                // If e stopped before another difference, that next difference
                // starts the next operation. This is the intended A/B/C split.
                const size_t nextStart = (e < len) ? nextDiff[e] : len;
                if (dp[nextStart] == INF) continue;

                const size_t cost = compact_line_size('r', beginO + s, e - s, e - s)
                                  + dp[nextStart];
                if (cost < dp[s]) {
                    dp[s] = cost;
                    choiceEnd[s] = e;
                    choiceNext[s] = nextStart;
                }
            }
        }

        if (dp[0] == INF) {
            out.push_back(region);
            return;
        }

        size_t s = nextDiff[0];
        while (s < len) {
            const size_t e = choiceEnd[s];
            if (e <= s || e > len) {
                out.push_back(region);
                return;
            }
            Diff d;
            d.type = "replace";
            d.offset = beginO + s;
            d.originalBegin = beginO + s;
            d.originalEnd = beginO + e;
            d.patchedBegin = beginP + s;
            d.patchedEnd = beginP + e;
            out.push_back(d);
            s = choiceNext[s];
        }
    };

    ProfileTimer profileOptimize("replacement optimizer");
    std::vector<Diff> optimizedDiffs;
    optimizedDiffs.reserve(diffs.size());
    for (size_t i = 0; i < diffs.size(); ++i) {
        if (diffs[i].type == "replace") optimize_replace_region(diffs[i], optimizedDiffs);
        else optimizedDiffs.push_back(diffs[i]);
    }
    diffs.swap(optimizedDiffs);

    /*
       Final coalescing is shared by both output formats.

       The optimizer above determines useful replacement regions, but the
       output format must not inherit an artificial 8/16/32 split.  Adjacent
       replace regions are therefore merged when the complete textual line
       becomes cheaper.  A small identical gap may also be absorbed when that
       saves the fixed operation overhead.

       This is deliberately done on the logical Diff list, before serialization,
       so normal and brute modes use exactly the same segmentation.
    */
    {
        auto line_size = [&](size_t offset, size_t originalSize, size_t patchedSize) -> size_t {
            size_t digits = 1;
            size_t v = offset;
            while (v >= 16) { v >>= 4; ++digits; }

            // Exact textual size including the newline for:
            //   v1: $OFFSET=NEW-OLD\n
            //   v2: $OFFSET=NEW\n
            if (bruteMode) {
                return digits + 3 + patchedSize * 2; // '$', '=', newline
            }

            return digits + 4 + originalSize * 2 + patchedSize * 2; // '$', '=', '-', newline
        };

        profileOptimize.report();
    profileOptimize.reset("final coalescing");
    std::vector<Diff> merged;
        merged.reserve(diffs.size());

        for (size_t i = 0; i < diffs.size(); ++i) {
            Diff cur = diffs[i];

            if (cur.type == "replace") {
                while (i + 1 < diffs.size() &&
                       diffs[i + 1].type == "replace") {
                    const Diff& next = diffs[i + 1];

                    const size_t curLenO = cur.originalEnd - cur.originalBegin;
                    const size_t curLenP = cur.patchedEnd - cur.patchedBegin;
                    const size_t nextLenO = next.originalEnd - next.originalBegin;
                    const size_t nextLenP = next.patchedEnd - next.patchedBegin;

                    if (curLenO != curLenP || nextLenO != nextLenP)
                        break;

                    if (next.originalBegin < cur.originalEnd ||
                        next.patchedBegin < cur.patchedEnd)
                        break;

                    const size_t gapO = next.originalBegin - cur.originalEnd;
                    const size_t gapP = next.patchedBegin - cur.patchedEnd;
                    if (gapO != gapP)
                        break;

                    // The regions can only be merged when the intervening
                    // bytes are identical in both files.
                    bool sameGap = true;
                    for (size_t q = 0; q < gapO; ++q) {
                        if (original[cur.originalEnd + q] !=
                            patched[cur.patchedEnd + q]) {
                            sameGap = false;
                            break;
                        }
                    }
                    if (!sameGap)
                        break;

                    const size_t mergedLen = curLenO + gapO + nextLenO;

                    const size_t separateCost =
                        line_size(cur.offset, curLenO, curLenP) +
                        line_size(next.offset, nextLenO, nextLenP);

                    const size_t mergedCost =
                        line_size(cur.offset, mergedLen, mergedLen);

                    // Merge only when it actually reduces the final textual
                    // patch. If equal, prefer fewer bytes of replacement data
                    // / fewer changes only when the textual size is equal.
                    if (mergedCost > separateCost)
                        break;

                    cur.originalEnd = next.originalEnd;
                    cur.patchedEnd = next.patchedEnd;
                    ++i;
                }
            }

            merged.push_back(cur);
        }

        diffs.swap(merged);
    }

    if (diffs.empty()) {
        std::wcerr << L"Error: no binary differences were generated after optimization.\n";
        return 6;
    }

    for (size_t i = 0; i < diffs.size(); ++i) {
        if (diffs[i].type == "replace" &&
            (diffs[i].originalEnd - diffs[i].originalBegin) !=
            (diffs[i].patchedEnd - diffs[i].patchedBegin)) {
            std::wcerr << L"Error: internal unequal replace operation generated.\n";
            return 7;
        }
    }

    profileOptimize.~ProfileTimer();

    ProfileTimer profileSha("SHA-256 + self-test");
    const std::string targetSha = sha256(original);
    const std::string patchedSha = sha256(patched);

    /*
       Self-test by reconstructing the patched file sequentially instead of
       applying thousands of vector erase/insert operations. This validates
       the generated operations while keeping the test linear in file size.
    */
    std::vector<uint8_t> reconstructed;
    reconstructed.reserve(patched.size());

    size_t sourcePos = 0;

    for (size_t i = 0; i < diffs.size(); ++i) {
        const Diff& d = diffs[i];

        if (d.originalBegin < sourcePos || d.originalBegin > original.size()) {
            std::wcerr << L"Error: invalid generated operation range during self-test.\n";
            return 7;
        }

        reconstructed.insert(
            reconstructed.end(),
            original.begin() + sourcePos,
            original.begin() + d.originalBegin);

        reconstructed.insert(
            reconstructed.end(),
            patched.begin() + d.patchedBegin,
            patched.begin() + d.patchedEnd);

        sourcePos = d.originalEnd;
    }

    if (sourcePos > original.size()) {
        std::wcerr << L"Error: invalid generated operation end during self-test.\n";
        return 7;
    }

    reconstructed.insert(
        reconstructed.end(),
        original.begin() + sourcePos,
        original.end());

    if (reconstructed != patched) {
        std::wcerr << L"Error: generated patch does not reproduce the patched file.\n";
        return 8;
    }

    std::ostringstream body;
    body << "# " << PATCHER_NAME_A << " patch file - generated automatically.\n";
    body << "# Comments may be added with lines starting with '#'.\n";
    body << "# Do not modify patch data.\n\n";
    body << "[patch]\n";
    body << "format_version=" << (bruteMode ? 2 : 1) << "\n";

    std::string patchNameUtf8;
    if (!wide_to_utf8(patchName, patchNameUtf8)) {
        std::wcerr << L"Error: invalid patch name (UTF-8).\n";
        return 9;
    }

    body << "name=" << patchNameUtf8 << "\n";

    std::string patchDescriptionUtf8;
    if (!wide_to_utf8(patchDescription, patchDescriptionUtf8)) {
        std::wcerr << L"Error: invalid patch description (UTF-8).\n";
        return 10;
    }
    if (!patchDescriptionUtf8.empty()) {
        body << "description=" << patchDescriptionUtf8 << "\n";
    }

    body << "target_sha256=" << targetSha << "\n";
    body << "patched_sha256=" << patchedSha << "\n";

    static const char* hex = "0123456789ABCDEF";
    for (size_t n = 0; n < diffs.size(); ++n) {
        const Diff& d = diffs[n];
        body << "$" << std::hex << std::uppercase << d.offset << std::dec << std::nouppercase;
        if (d.type == "replace") {
            body << "=";
            for (size_t i = d.patchedBegin; i < d.patchedEnd; ++i)
                body << hex[patched[i] >> 4] << hex[patched[i] & 15];
            if (!bruteMode) {
                body << "-";
                for (size_t i = d.originalBegin; i < d.originalEnd; ++i)
                    body << hex[original[i] >> 4] << hex[original[i] & 15];
            }
        } else if (d.type == "insert") {
            body << "+";
            for (size_t i = d.patchedBegin; i < d.patchedEnd; ++i)
                body << hex[patched[i] >> 4] << hex[patched[i] & 15];
        } else {
            body << "-";
            if (bruteMode) {
                body << (d.originalEnd - d.originalBegin);
            } else {
                for (size_t i = d.originalBegin; i < d.originalEnd; ++i)
                    body << hex[original[i] >> 4] << hex[original[i] & 15];
            }
        }        body << "\n";
    }

	//body << "\n";

    debugStageStart = std::chrono::steady_clock::now();
    const std::string bodyWithoutHash = body.str();
    debug_report("serialize patch body", debugStageStart);
    debugStageStart = std::chrono::steady_clock::now();

    const std::string patchSha = sha256_patch_text(bodyWithoutHash);

    const size_t headerEnd = bodyWithoutHash.find("patched_sha256=");
    size_t insertPos = std::string::npos;
    if (headerEnd != std::string::npos) {
        insertPos = bodyWithoutHash.find('\n', headerEnd);
        if (insertPos != std::string::npos) ++insertPos;
    }
    if (insertPos == std::string::npos) {
        std::wcerr << L"Internal error: patch header insertion point is missing.\n";
        return 10;
    }

    std::string finalText = bodyWithoutHash;
    finalText.insert(insertPos, "patch_sha256=" + patchSha + "\n\n");
    debug_report("patch SHA-256 + finalize text", debugStageStart);
    debugStageStart = std::chrono::steady_clock::now();

    std::vector<uint8_t> outputBytes;
    if (compressOutput) {
        std::vector<uint8_t> plain(finalText.begin(), finalText.end());
        std::string compressionError;
        if (!bz2_compress(plain, outputBytes, compressionError)) {
            std::wcerr << L"Error: " << std::wstring(compressionError.begin(), compressionError.end()) << L"\n";
            return 11;
        }
    } else {
        outputBytes.assign(finalText.begin(), finalText.end());
    }

    std::ofstream out(outputPath.c_str(), std::ios::binary | std::ios::trunc);
    if (!out) {
        std::wcerr << L"Error: unable to write the patch.\n";
        return 12;
    }
    if (!outputBytes.empty()) {
        out.write(reinterpret_cast<const char*>(outputBytes.data()), static_cast<std::streamsize>(outputBytes.size()));
    }
    if (!out) {
        std::wcerr << L"Error: patch write failed.\n";
        return 13;
    }
    debug_report("write output patch", debugStageStart);

    print_wline(L"Generation completed.");
    print_wline(std::wstring(L"  Patch      : ") + outputPath);
    print_wline(L"  Operations : " + std::to_wstring(diffs.size()));
    print_wline(std::wstring(L"  Original SHA-256: ") + std::wstring(targetSha.begin(), targetSha.end()));
    print_wline(std::wstring(L"  Patched SHA-256: ") + std::wstring(patchedSha.begin(), patchedSha.end()));
    print_wline(std::wstring(L"  Patch SHA-256: ") + std::wstring(patchSha.begin(), patchSha.end()));
    return 0;
}

static int apply_patch_file(const wchar_t* filePath, const wchar_t* patchPath, const wchar_t* outputPathArg) {
    std::wstring patchFile(patchPath);
    Patch patch;
    std::wstring error;

    print_wline(PATCHER_NAME L" - applying patch...");
    print_wline(std::wstring(L"  File  : ") + filePath);
    print_wline(std::wstring(L"  Patch : ") + patchPath);

    std::ifstream patchStream(patchFile.c_str(), std::ios::binary);
    if (!patchStream) {
        std::wcerr << L"Error: unable to open the patch.\n";
        return 3;
    }
    std::ostringstream patchBuffer;
    patchBuffer << patchStream.rdbuf();
    std::string patchRaw = patchBuffer.str();

    if (has_bz2_extension(patchFile)) {
        std::vector<uint8_t> compressed(patchRaw.begin(), patchRaw.end());
        std::vector<uint8_t> decompressed;
        std::string decompressionError;
        if (!bz2_decompress(compressed, decompressed, decompressionError)) {
            std::wcerr << L"Error: " << std::wstring(decompressionError.begin(), decompressionError.end()) << L"\n";
            return 4;
        }
        patchRaw.assign(reinterpret_cast<const char*>(decompressed.data()), decompressed.size());
    }

    if (!parse_patch_text(patchRaw, patch, error)) {
        std::wcerr << L"Error: " << error << L"\n";
        return 5;
    }

    const std::string patchActual = sha256_patch_text(patchRaw);
    if (patchActual != patch.patchSha) {
        std::wcerr << L"Error: invalid patch SHA-256 or modified patch.\n";
        return 6;
    }

    std::vector<uint8_t> data;
    if (!read_all(filePath, data)) {
        std::wcerr << L"Error: unable to read the target file.\n";
        return 7;
    }

    const std::string actualSha = sha256(data);
    print_wline(std::wstring(L"  Current SHA-256: ") + std::wstring(actualSha.begin(), actualSha.end()));

    if (actualSha == patch.patchedSha) {
        print_wline(L"Information: the file is already patched.");
        return 0;
    }

    if (actualSha != patch.targetSha) {
        std::wcerr << L"Warning: the file SHA-256 does not match the expected version.\n";
        std::wcerr << L"  Expected: " << std::wstring(patch.targetSha.begin(), patch.targetSha.end()) << L"\n";
        return 8;
    }

    if (!patch_bytes(data, patch, error)) {
        std::wcerr << L"Error: " << error << L"\n";
        return 9;
    }

    const std::string resultSha = sha256(data);
    print_wline(std::wstring(L"  Final SHA-256  : ") + std::wstring(resultSha.begin(), resultSha.end()));

    if (resultSha != patch.patchedSha) {
        std::wcerr << L"Error: final SHA-256 does not match the patch. No file was written.\n";
        return 10;
    }

    std::wstring outputPath;
    if (outputPathArg != NULL && outputPathArg[0] != L'\0') {
        outputPath = outputPathArg;
    } else {
        outputPath = default_patched_output_path(std::wstring(filePath));
    }

    if (!save_atomic(outputPath, data, error)) {
        std::wcerr << L"Error: " << error << L"\n";
        return 11;
    }

    print_wline(std::wstring(L"  Output : ") + outputPath);
    print_wline(L"Patch applied successfully.");
    return 0;
}

int wmain(int argc, wchar_t* argv[]) {
    if (argc < 2) {
        print_usage();
        return 2;
    }

    ExecutionTimer executionTimer;
    const auto debugWmainStart = std::chrono::steady_clock::now();

    std::wstring mode;
    bool compressOutput = false;
    bool bruteMode = false;
    std::wstring name = L"Generated patch";
    std::wstring description;
    std::vector<std::wstring> positional;

    for (int i = 1; i < argc; ++i) {
        const std::wstring raw = argv[i];
        const std::wstring option = normalize_option(raw);

        if (option == L"-debug") {
            g_debug = true;
        } else if (option == L"-g" || option == L"-generate") {
            if (!mode.empty() && mode != L"generate") {
                print_usage();
                return 2;
            }
            mode = L"generate";
        } else if (option == L"-p" || option == L"-patch") {
            if (!mode.empty() && mode != L"patch") {
                print_usage();
                return 2;
            }
            mode = L"patch";
        } else if (option == L"-c" || option == L"-compress") {
            compressOutput = true;
        } else if (option == L"-b" || option == L"-brute") {
            bruteMode = true;
        } else if (option == L"-n" || option == L"-name") {
            if (i + 1 >= argc) {
                print_usage();
                return 2;
            }
            name = argv[++i];
        } else if (option == L"-d" || option == L"-description") {
            if (i + 1 >= argc) {
                print_usage();
                return 2;
            }
            description = argv[++i];
        } else if (!raw.empty() && raw[0] == L'-') {
            print_usage();
            return 2;
        } else {
            positional.push_back(raw);
        }
    }

    // if (g_debug) {
        // const double processStart = std::chrono::duration<double>(
            // debugWmainStart - g_process_start).count();
        // const double parsed = std::chrono::duration<double>(
            // std::chrono::steady_clock::now() - debugWmainStart).count();

        // std::cerr << "[DEBUG] process startup -> wmain : "
                  // << std::fixed << std::setprecision(3)
                  // << processStart << " s\n";
        // std::cerr << "[DEBUG] argument parsing : "
                  // << std::fixed << std::setprecision(3)
                  // << parsed << " s\n";
    // }

    if (mode == L"generate") {
        if (positional.size() < 2 || positional.size() > 3) {
            print_usage();
            return 2;
        }

        std::wstring output;
        if (positional.size() == 3) {
            output = compressOutput
                ? ensure_compressed_patch_extension(positional[2])
                : ensure_patch_extension(positional[2]);
        } else {
            output = compressOutput
                ? std::wstring(positional[0]) + L".patch.bz2"
                : std::wstring(positional[0]) + L".patch";
        }

        return generate_patch(positional[0].c_str(), positional[1].c_str(),
                              output, name, description, compressOutput, bruteMode);
    }

    if (mode == L"patch") {
        if (compressOutput || bruteMode || !description.empty() || name != L"Generated patch" ||
            positional.size() < 2 || positional.size() > 3) {
            print_usage();
            return 2;
        }
        return apply_patch_file(positional[0].c_str(), positional[1].c_str(),
                                positional.size() == 3 ? positional[2].c_str() : NULL);
    }

    print_usage();
    return 2;
}
