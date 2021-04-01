#pragma once

#include <string>
#include <map>
#include <vector>

using StringMap = std::map<std::string, std::string>;

std::vector<BYTE> WriteStringMapDataProtect(const StringMap& map);
StringMap ReadStringMapDataProtect(const std::vector<BYTE>& bytes);

std::string WriteStringMapOpenSSL(const StringMap& map);
StringMap ReadStringMapOpenSSL(std::string encryptedMap);
