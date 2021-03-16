#pragma once

#include <string>
#include <map>

using StringMap = std::map<std::string, std::string>;
//std::string WriteStringMap(const StringMap& map);
//StringMap ReadStringMap(std::string jsonMap);

std::string WriteStringMapEncrypted(const StringMap& map);
StringMap ReadStringMapDecrypted(std::string encryptedMap);
