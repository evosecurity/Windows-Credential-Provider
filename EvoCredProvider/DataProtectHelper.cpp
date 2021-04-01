#include "pch.h"
#include <atlbase.h>
#include "DataProtectHelper.h"
#include "CoreLibs_/nlohmann/json.hpp"
#include <decrypt.h>

#include <dpapi.h>
#pragma comment(lib,"crypt32.lib")

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

template <class T>
std::vector<BYTE> WriteMapDataProtected(const std::map<std::string, T>& map)
{
    nlohmann::json j;

    j["map"] = map;

    std::string s = to_string(j);

    DATA_BLOB blobIn = { (DWORD) s.length() + 1, (BYTE*)&s.front() };

    BlobOut blobOut;

    std::vector<BYTE> bytes;

    CRYPTPROTECT_PROMPTSTRUCT cpps{ sizeof(cpps) };
    if (CryptProtectData(&blobIn, L"Entropy", nullptr, nullptr, &cpps, 0, &blobOut))
    {
        bytes.resize(blobOut.cbData);
        memcpy(&bytes.front(), blobOut.pbData, blobOut.cbData);
    }

    return bytes;
}

template <class T>
std::map<std::string, T> ReadMapDataProtected(std::vector<BYTE> bytes)
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

StringMap ReadStringMapDataProtect(const std::vector<BYTE>& bytes)
{
    return ReadMapDataProtected<std::string>(bytes);
}

std::vector<BYTE> WriteStringMapDataProtect(const StringMap& map)
{
    return WriteMapDataProtected<std::string>(map);
}



std::string shared_key = "mvXcphkyhzAGYtFgtFtR5k7TVh9mk7PL";

std::string w2s(LPCWSTR lpwz)
{
    int len = (int)wcslen(lpwz);
    int nNeeded = WideCharToMultiByte(CP_UTF8, 0, lpwz, len, nullptr, 0, nullptr, NULL) + 1;
    auto buf = std::make_unique<char[]>(nNeeded);
    WideCharToMultiByte(CP_UTF8, 0, lpwz, len, buf.get(), nNeeded, nullptr, nullptr);
    return buf.get();
}

std::string remove(std::string s, char c)
{
    size_t pos;
    while (0xffffffffffffffff != (pos = s.find_last_of(c)))
    {
        s.erase(pos, 1);
    }
    return s;
}


std::string clsid_provider = "a81f782d-cf30-439a-bad8-645d9862ea99"; // CLSID of cred provider

std::string get_shared_key()
{
    return remove(clsid_provider, '-');
}

std::string GetMachineGuid(bool bStripped = true)
{
    ATL::CRegKey key;
    key.Open(HKEY_LOCAL_MACHINE, _T("Software\\Microsoft\\Cryptography\\"), KEY_READ);

    TCHAR buf[MAX_PATH] = {};
    ULONG nChars = _countof(buf);
    LRESULT res = key.QueryStringValue(_T("MachineGuid"), buf, &nChars);
    std::string s = w2s(buf);
    if (s.length() != 36)
        s = clsid_provider;
    return bStripped ? remove(s, '-') : s;
}

std::string GetMachineIV()
{
    std::string sMachineGuid = GetMachineGuid();
    return sMachineGuid.substr(0, 16);
}

std::string GetMachineSalt()
{
    auto sMachineGuid = GetMachineGuid();
    return sMachineGuid.substr(sMachineGuid.length() - 16);
}


template <class T>
std::string MapToJson(std::map<std::string, T> map)
{
    nlohmann::json j;
    j["map"] = map;

    return to_string(j);
}

template <class T>
std::map<std::string, T> JsonToMap(std::string json_string)
{
    auto json = nlohmann::json::parse(json_string);
    if (json.contains("map"))
        return json["map"];
    return std::map<std::string, T>();
}

StringMap ReadStringMap(std::string s)
{
    if (!s.empty())
    {
        try
        {
            return JsonToMap<std::string>(s);
        }
        catch (...)
        {
        }
    }

    return StringMap();
}

StringMap ReadEncryptedMap(std::string s)
{
    auto json_string = RubyDecode(s, GetMachineSalt(), GetMachineIV(), get_shared_key());
    return ReadStringMap(json_string.c_str());
    return StringMap();
}


std::string WriteStringMap(const StringMap& map)
{
    return MapToJson(map);
}

secure_string WriteEncryptedMap(const StringMap& map)
{
    secure_string s = MapToJson(map).c_str();
    return RubyEncode(s, GetMachineSalt(), GetMachineIV(), get_shared_key());
}

secure_string to_secure_string(const std::string s)
{
    return secure_string(s.c_str());
}

std::string WriteStringMapOpenSSL(const StringMap& map)
{
    auto s = MapToJson(map);
    return RubyEncode(to_secure_string(s), GetMachineSalt(), GetMachineIV(), get_shared_key()).c_str();
}

StringMap ReadStringMapOpenSSL(std::string encryptedStringMap)
{
    auto json_string = RubyDecode(encryptedStringMap, GetMachineSalt(), GetMachineIV(), get_shared_key());
    return ReadStringMap(json_string.c_str());
    return StringMap();
}


#ifdef _DEBUG

extern "C" __declspec(dllexport) void __stdcall TestReadWriteMap()
{
    using namespace std;

    map<string, string> the_map;
    the_map["name"] = "joe";
    the_map["city"] = "tulsa";

    auto s = WriteStringMap(the_map);
    auto m = ReadStringMap(s);
}

extern "C" __declspec(dllexport) void __stdcall TestReadWriteCryptMap()
{
    using namespace std;

    map<string, string> the_map;
    the_map["name"] = "joe";
    the_map["city"] = "tulsa";

    auto s = WriteEncryptedMap(the_map);

    auto m = ReadEncryptedMap(s.c_str());

}

extern "C" __declspec(dllexport) void __stdcall TestReadWriteCryptMapDataProtected()
{
    using namespace std;

    map<string, string> the_map;
    the_map["name"] = "joe";
    the_map["city"] = "tulsa";

    auto a = WriteStringMapDataProtect(the_map);
    auto m = ReadStringMapDataProtect(a);

}

#endif

