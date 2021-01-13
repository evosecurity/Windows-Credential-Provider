#pragma once

#include "EvoSecureString.h"

typedef unsigned char byte;

secure_string RubyDecode(std::string data, std::string salt, std::string iv, std::string key);
secure_string RubyEncode(secure_string data, std::string salt, std::string iv, std::string key);
