#include "compress.h"

#include <bzlib.h>
#include <string>
#include <vector>

bool bz2_compress(const std::vector<unsigned char>& in,
                  std::vector<unsigned char>& out,
                  std::string& err)
{
    if (in.empty()) {
        out.clear();
        return true;
    }

    unsigned int srcLen = static_cast<unsigned int>(in.size());
    unsigned int destLen = srcLen + (srcLen / 100) + 601;
    out.resize(destLen);

    int rc = BZ2_bzBuffToBuffCompress(
        reinterpret_cast<char*>(out.data()), &destLen,
        const_cast<char*>(reinterpret_cast<const char*>(in.data())), srcLen,
        9, 0, 30);

    if (rc != BZ_OK) {
        err = "bzip2 compression failed (error " + std::to_string(rc) + ")";
        out.clear();
        return false;
    }

    out.resize(destLen);
    return true;
}

bool bz2_decompress(const std::vector<unsigned char>& in,
                    std::vector<unsigned char>& out,
                    std::string& err)
{
    if (in.empty()) {
        out.clear();
        return true;
    }

    unsigned int destLen = static_cast<unsigned int>(in.size() * 8 + 1024);
    out.resize(destLen);

    while (true) {
        unsigned int currentLen = destLen;
        int rc = BZ2_bzBuffToBuffDecompress(
            reinterpret_cast<char*>(out.data()), &currentLen,
            const_cast<char*>(reinterpret_cast<const char*>(in.data())),
            static_cast<unsigned int>(in.size()), 0, 0);

        if (rc == BZ_OK) {
            out.resize(currentLen);
            return true;
        }

        if (rc != BZ_OUTBUFF_FULL) {
            err = "bzip2 decompression failed (error " + std::to_string(rc) + ")";
            out.clear();
            return false;
        }

        destLen *= 2;
        out.resize(destLen);
    }
}
