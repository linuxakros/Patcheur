#pragma once
#include <string>
#include <vector>

bool bz2_compress(const std::vector<unsigned char>& in,
                  std::vector<unsigned char>& out,
                  std::string& err);

bool bz2_decompress(const std::vector<unsigned char>& in,
                    std::vector<unsigned char>& out,
                    std::string& err);
