#include "pch.h"
#include "DataProtectHelper.h"
#pragma comment(lib,"crypt32.lib")

template <class T>
std::vector<BYTE> StoreMap(std::map<std::string, T> map)
{
    nlohmann::json j;

    j["map"] = map;

    string s = to_string(j);

    DATA_BLOB blobIn = { s.length() + 1, (BYTE*)&s.front() };

    BlobOut blobOut;

    CRYPTPROTECT_PROMPTSTRUCT cpps{ sizeof(cpps) };
    CryptProtectData(&blobIn, L"Entropy", nullptr, nullptr, &cpps, 0, &blobOut);

    std::vector<BYTE> bytes(blobOut.cbData);
    memcpy(&bytes.front(), blobOut.pbData, blobOut.cbData);

    return bytes;
}

template <class T>
std::map<std::string, T> ReadMap(std::vector<BYTE> bytes)
{
    std::map<std::string, T> mapReturn;
    CRYPTPROTECT_PROMPTSTRUCT cpps{ sizeof(cpps) };
    DATA_BLOB blobDecrypt = { (DWORD) bytes.size(), &bytes.front() };
    if (bytes.size() > 0)
    {
        LocalString pwstr;
        BlobOut blobOut;
        if (CryptUnprotectData(&blobDecrypt, &pwstr, nullptr, NULL, &cpps, 0, &blobOut))
        {
            auto j = nlohmann::json::parse(blobOut.pbData);
            return j["map"];
        }
    }
    return mapReturn;
}

std::map<std::string, std::string> ReadStringMap(std::vector<BYTE> bytes)
{
    return ReadMap<std::string>(bytes);
}