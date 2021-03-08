#pragma once

#include <dpapi.h>
#include <string>
#include <vector>
#include <map>
#include "CoreLibs_/nlohmann/json.hpp"

class BlobOut : public DATA_BLOB
{
public:
    BlobOut()
    {
        cbData = 0;
        pbData = nullptr;
    }
    ~BlobOut()
    {
        if (pbData)
        {
            LocalFree(pbData);
        }
    }

};

class LocalString
{
public:
    ~LocalString()
    {
        if (pwstr) {
            LocalFree(pwstr);
            pwstr = nullptr;
        }
    }
    LPWSTR* operator&() {
        return &pwstr;
    }

    operator LPWSTR()
    {
        return pwstr;
    }
    LPWSTR pwstr = nullptr;
};


std::vector<BYTE> StoreStringMap(std::map<std::string, std::string> map);

std::map<std::string, std::string> ReadStringMap(std::vector<BYTE> bytes);
