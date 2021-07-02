// EvoApiTest.cpp : This file contains the 'main' function. Program execution begins and ends there.
//
#include <windows.h>
#include <iostream>
#include <EvoApi.h>
#include <decrypt.h>
#include <atlbase.h>
#include <Lmwksta.h>
#include <StrSafe.h>
#include <LMAPIbuf.h>
#include <LMJoin.h>
#include <wincred.h>
#include <NTSecAPI.h>
#include <vector>
#include <codecvt>

#pragma warning(disable : 4996)
#pragma comment(lib, "netapi32.lib")
#pragma comment(lib, "credui.lib")
#pragma comment(lib, "secur32")

using namespace std;

WCHAR wszDefaultEnvironmentUrl[] = L"https://evo.evosecurity.io";

wstring GlobalUserName;
secure_wstring GlobalPassword;

bool Authenticate( EvoAPI::AuthenticateResponse& response)
{
    EvoAPI EvoApi{};
    return EvoApi.Authenticate(GlobalUserName, GlobalPassword, response);
}

bool ValidateMFA(EvoAPI::ValidateMFAResponse& response)
{
    std::wstring sAuthCode;
    cout << "Enter auth code:  ";
    wcin >> sAuthCode;

    EvoAPI EvoApi{};
    return EvoApi.ValidateMFA(sAuthCode.c_str(), GlobalUserName, GlobalPassword.c_str(), response);
}

bool CheckLogin(std::string request_id, std::string ipAddress, EvoAPI::CheckLoginResponse& response)
{
    EvoAPI evoapi;
    return evoapi.CheckLoginRequest(request_id.c_str(), ipAddress, response);
}

extern void TestJson();

std::string wstring_to_string(const std::wstring& ws)
{
    std::string sret;
    int nlen;
    if ((nlen = WideCharToMultiByte(CP_THREAD_ACP, 0, ws.c_str(), (int)ws.length(), 0, 0, 0, 0)) > 0)
    {
        string s;
        s.resize(nlen);
        if (nlen == WideCharToMultiByte(CP_THREAD_ACP, 0, ws.c_str(), (int)ws.length(), &s.front(), nlen, 0, 0))
            sret = s;
    }

    return sret;
}

struct CredentialPair
{
    SecureWString user;
    SecureWString pw;
};

typedef std::vector<CredentialPair> CredentialPairCollection;

bool ParseCredPair(const SecureWString& credPairString, CredentialPair& credPair)
{
    size_t find = credPairString.find(L',');
    if (find == credPairString.npos)
        return false;

    credPair = { credPairString.substr(0, find), credPairString.substr(find + 1) };
    return true;
}


bool GetCredEntriesFromPayloadString(const SecureWString& wData, CredentialPairCollection& credentialEntries)
{
    if (wData.length() == 0)
        return false;

    size_t posStart = 0;
    size_t pos = 0;
    while (wData.npos != (pos = wData.find_first_of(L'|', posStart)))
    {
        SecureWString credPairString = wData.substr(posStart, pos - posStart);

        CredentialPair credPair;

        if (!ParseCredPair(credPairString, credPair))
            return false;
        credentialEntries.push_back(credPair);

        posStart = pos + 1;
    }

    if (posStart < wData.length())
    {
        CredentialPair credPair;
        if (!ParseCredPair(wData.substr(posStart), credPair))
            return false;
        credentialEntries.push_back(credPair);
    }
    return !credentialEntries.empty();
}

namespace EvoSolutionX
{
    std::wstring s2ws(const std::string& s)
    {
        using convert_typeX = std::codecvt_utf8<wchar_t>;
        std::wstring_convert<convert_typeX, wchar_t> converterX;

        return converterX.from_bytes(s);
    }
}

bool GetCredsFromPayload(EvoAPI::LoginResponse& response, CredentialPairCollection& credPairs)
{
    std:: string skey;
    ATL::CRegKey rkey;
    if (S_OK == rkey.Open(HKEY_LOCAL_MACHINE, L"SOFTWARE\\EvoSecurity\\EvoLogin-CP\\", KEY_READ))
    {
        WCHAR szBuf[MAX_PATH];
        ULONG ulRead = _countof(szBuf);
        rkey.QueryStringValue(L"specialKey", szBuf, &ulRead);

        skey = wstring_to_string(szBuf);
    }
    if (skey.empty())
    {
        cout << "specialKey not in registry" << endl;
    }
    try
    {
        secure_string sData = RubyDecode(response.data, response.salt, response.iv, skey);

        SecureWString wData = EvoSolutionX::s2ws(sData.c_str()).c_str();
        return GetCredEntriesFromPayloadString(wData, credPairs);

    }
    catch (...)
    {

    }
    return false;
}

void WriteBasicResponse(const EvoAPI::BasicResponse& resp)
{
    cout << "Http code: " << resp.httpStatus << ", raw_response: " << resp.raw_response << endl;
}

void TheFuncExtToLog(LPCSTR message, LPCSTR filename, int lineno, bool flag)
{
    cout << "[" << filename << ":" << lineno << "] " << message << endl;
}

void TestMFA10()
{
    cout << "Testing validate_mfa" << endl;
    EvoAPI::ValidateMFAResponse validateMfaResponse;
    bool bValidateMFA = ValidateMFA(validateMfaResponse);
    WriteBasicResponse(validateMfaResponse);
    if (bValidateMFA) {
        cout << "validate_mfa succeeded" << endl;

        CredentialPairCollection credPairs;
        if (GetCredsFromPayload(validateMfaResponse, credPairs))
        {
            for (auto credPair : credPairs)
            {
                wcout << "user: " << credPair.user << endl << "pw:   " << credPair.pw << endl;
            }
        }
        else
        {
            cout << "failed getting payload creds" << endl;
        }
    }
    else {
        cout << "validate_mfa failed" << endl;
    }
}


void TestPoll10(std::string ipAddress)
{
    EvoAPI::AuthenticateResponse authenticateResponse;
    bool bAuth = Authenticate(authenticateResponse);
    WriteBasicResponse(authenticateResponse);
    if (bAuth && !authenticateResponse.request_id.empty())
    {
        cout << "Authenticating: " << authenticateResponse.request_id << endl;

        bool LoginGood = false;
        EvoAPI::CheckLoginResponse checkLoginResponse;
        for (int i = 0; i < 10; ++i)
        {
            Sleep(1000);
            cout << "Checking ...  " << endl;
            LoginGood = CheckLogin(authenticateResponse.request_id, ipAddress, checkLoginResponse);
            WriteBasicResponse(checkLoginResponse);
            if (LoginGood)
            {
                cout << "\nChecked ok" << endl;
                break;
            }
            else {
            }
        }

        if (LoginGood)
        {
            CredentialPairCollection credPairs;
            if (GetCredsFromPayload(checkLoginResponse, credPairs))
            {
                for (auto& cred : credPairs)
                {
                    wcout << "user: " << cred.user << endl << "pw:   " << cred.pw << endl;

                }
            }
            else
            {
                cout << "Failed to get creds" << endl;
            }
        }
    }
    else {
        cout << "Authenticate failed ..." << endl;
        cout << "Http response: " << authenticateResponse.httpStatus << ", message: " << authenticateResponse.raw_response << endl;
    }
}


void TestMFA90()
{
    std::wstring sAuthCode;
    cout << "Enter auth code:  ";
    wcin >> sAuthCode;

    EvoAPI EvoApi{};
    EvoAPI::ValidateMFA90Response response;
    bool bSuccess = EvoApi.ValidateMFA90(sAuthCode.c_str(), GlobalUserName, response);
    if (bSuccess) {
        cout << "validate_mfa succeeded" << endl;
    }
    else {
        cout << "validate_mfa failed" << endl;

    }

}

void TestPoll90(std::string ipaddress)
{
    cout << "Testing polling" << endl;
    
    EvoAPI::AuthenticateResponse response;
    EvoAPI evoApi;
    bool bSuccess = evoApi.Authenticate90(GlobalUserName, response);
    if (bSuccess) {
        cout << "Authenticate90 succeeded" << endl;
    }
    else {
        cout << "Authenticate90 failed" << endl;
        return;
    }

    cout << "Authenticating: " << response.request_id << endl;

    bool LoginGood = false;
    for (int i = 0; i < 10; ++i) {
        Sleep(1000);

        cout << "Checking ...  " << endl;

        EvoAPI evo;
        EvoAPI::CheckLogin90Response checkLogin90Response;
        LoginGood = evo.CheckLoginRequest(response.request_id, ipaddress, checkLogin90Response);
        if (LoginGood)
        {
            cout << "\nChecked ok" << endl;
            break;
        }
        else {
        }
    }

    if (LoginGood) {
        cout << "Good polling" << endl;
    }
    else {
        cout << "Failed polling" << endl;
    }

}


wstring GetAzureADJoinDomain()
{
    wstring wret;
    PDSREG_JOIN_INFO pJoinInfo = NULL;
    NetGetAadJoinInformation(NULL, &pJoinInfo);

    if (pJoinInfo)
    {
        wstring email =  pJoinInfo->pszJoinUserEmail;
        size_t find = email.find('@');
        if (find != wstring::npos)
            wret = email.substr(find + 1);
        NetFreeAadJoinInformation(pJoinInfo);
    }

    return wret;
}

struct LSAHANDLE
{
    HANDLE handle = 0;

    operator HANDLE()
    {
        return handle;
    }
    ~LSAHANDLE()
    {
        if (handle != NULL)
            LsaDeregisterLogonProcess(handle);
    }
    HANDLE* operator&()
    {
        ATLASSERT(handle == nullptr);
        return &handle;
    }
};

template <size_t SIZE = 256>
struct LsaString : public LSA_STRING
{

    LsaString()
    {
        MaximumLength = SIZE;
        Length = 0;
        Buffer = pBuf.get();
    }

    LsaString(LPCSTR pWhat)
    {
        MaximumLength = SIZE;
        Length = 0;
        Buffer = pBuf.get();
        Init(pWhat);
    }
    void Init(LPCSTR pWhat)
    {
        size_t len = strlen(pWhat);
        if (len >= SIZE)
            throw;
        strcpy(Buffer, pWhat);
        Length = (USHORT) len;
    }
    unique_ptr<char[]> pBuf = make_unique< char[] >(SIZE);
};

class CoTaskMemory
{
    void* pv = nullptr;
public:
    ~CoTaskMemory()
    {
        if (pv)
        {
            CoTaskMemFree(pv);
        }
    }

    LPVOID* operator&() {
        return &pv;
    }
    operator bool()
    {
        return pv != nullptr;
    }
};

string GetExternalIPAddress()
{
    EvoAPI api(L"https://ifconfig.me");
    auto resp = api.Connect(L"/ip", "", L"GET");
    return resp.sResponse;
}


void TestCredEntriesCode(LPCWSTR data)
{
    CredentialPairCollection credPairs;
    if (!GetCredEntriesFromPayloadString(data, credPairs))
        cout << "Bad payload" << endl;

    for (const auto& credPair : credPairs)
    {
        wcout << "Username: " << credPair.user << endl << "Password: " << credPair.pw << endl;
    }

}

void TestCredEntriesCode()
{
    TestCredEntriesCode(L"");
    TestCredEntriesCode(L"bad|data");
    TestCredEntriesCode(L"wilma,flintstone");
    TestCredEntriesCode(L"fred,flintstone|barney,rubble");
}

int _tmain(int argc, wchar_t* argv[])
{
    auto ipAddress = GetExternalIPAddress();
#if 0
    wstring me(_T("MYLOGING"));
    wstring url(_T("Header"));
    wstring message(_T("Enter credentials for ..."));

    CREDUI_INFOW credInfo;
    credInfo.pszCaptionText = url.c_str();
    credInfo.hbmBanner = nullptr;
    credInfo.hwndParent = NULL;
    credInfo.pszMessageText = message.c_str();
    credInfo.cbSize = sizeof(CREDUI_INFOW);

    ULONG authPackage = 0;

    LSAHANDLE lsaHandle;
    LsaConnectUntrusted(&lsaHandle);

    //LsaString<> lsaString("EvoCredProvider");
    //LsaString<> lsaString(MICROSOFT_KERBEROS_NAME_A);
    //LsaString<> lsaString(NEGOSSP_NAME_A);
    LsaString<> lsaString(MSV1_0_PACKAGE_NAME);


    ULONG ulPackage = 0;
    //LsaLookupAuthenticationPackage(lsaHandle, &lsaString, &ulPackage);

    ulPackage = 0;

    ULONG blobSize = 0;

    DWORD dwFlags = CREDUIWIN_GENERIC; //CREDUIWIN_SECURE_PROMPT
    dwFlags = CREDUIWIN_CHECKBOX;
    dwFlags = CREDUIWIN_IN_CRED_ONLY;
    dwFlags = CREDUIWIN_SECURE_PROMPT;

    CoTaskMemory blob;
    CredUIPromptForWindowsCredentials(&credInfo, 0, &ulPackage, NULL, 0, &blob, &blobSize, FALSE, dwFlags);

    if (blob) {

    }

    return 0;

#endif
    wstring AzureADDomain = GetAzureADJoinDomain();

    std::wstring domainNameBuf = GetDomainOrMachineIncludingRegistry();
    wcout << "Domain name (or Computer name): " << domainNameBuf << endl;

    WCHAR domain_name[256];
    WKSTA_INFO_100* info = NULL;
    if (ERROR_SUCCESS == NetWkstaGetInfo(NULL, 100, (LPBYTE*) &info) &&
        SUCCEEDED(StringCchCopy(domain_name, ARRAYSIZE(domain_name), info->wki100_langroup))) {
        wcout << "Other domain name: " << domain_name << endl;
    }
    if (info != NULL)
        NetApiBufferFree(info);


    if (argc <2 ) {
        cout << "Enter username: ";
        wcin >> GlobalUserName;
    }
    else {
        GlobalUserName = argv[1];
        wcout << L"User name: " << GlobalUserName << endl;
    }


    if (argc < 3) {
        cout << "Enter password: ";
        wcin >> GlobalPassword;
    }
    else {
        GlobalPassword = argv[2];
        wcout << L"Password: " << GlobalPassword << endl;
    }

    //EvoAPI::SetCharWidthLog(TheFuncToLog);
    EvoAPI::SetCharWidthExtLogFunc(TheFuncExtToLog);

    wcout << L"GlobalUserName=" << GlobalUserName << endl;

    //TestMFA90();
    //TestPoll90(ipAddress);

    //TestMFA10();
    //GlobalUserName = L"willcoxson@gmail.com";
    //GlobalUserName = L"jorge.rodriguez@evoauth.com";


    TestCredEntriesCode();


    TestPoll10(ipAddress);

}
