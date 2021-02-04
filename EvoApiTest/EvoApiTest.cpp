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

#pragma warning(disable : 4996)
#pragma comment(lib, "netapi32.lib")

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

bool CheckLogin(std::string request_id, EvoAPI::CheckLoginResponse& response)
{
    EvoAPI evoapi;
    return evoapi.CheckLoginRequest(request_id.c_str(), response);
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

bool GetCredsFromPayload(EvoAPI::LoginResponse& response, secure_string& user, secure_string& pw)
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

        size_t find = sData.find(',');

        user = sData.substr(0, find);
        pw = sData.substr(find + 1);

        return true;
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

int _tmain(int argc, wchar_t* argv[])
{
    DWORD bufSize = MAX_PATH;
    TCHAR domainNameBuf[MAX_PATH];
    GetComputerNameEx(ComputerNameDnsDomain, domainNameBuf, &bufSize);
    wcout << "Domain name: " << domainNameBuf << endl;

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


    EvoAPI::ValidateMFAResponse validateMfaResponse;
    bool bValidateMFA = ValidateMFA(validateMfaResponse);
    WriteBasicResponse(validateMfaResponse);
    if (bValidateMFA) {
        cout << "validate_mfa succeeded" << endl;

        secure_string user, pw;
        if (GetCredsFromPayload(validateMfaResponse, user, pw))
        {
            cout << "user: " << user << endl << "pw:   " << pw << endl;
        }
        else
        {
            cout << "failed getting payload creds" << endl;
        }
    }
    else {
        cout << "validate_mfa failed" << endl;
    }

    EvoAPI::AuthenticateResponse authenticateResponse;
    bool bAuth = Authenticate(authenticateResponse);
    WriteBasicResponse(authenticateResponse);
    if ( bAuth && !authenticateResponse.request_id.empty())
    {
        cout << "Authenticating: " << authenticateResponse.request_id << endl;

        bool LoginGood = false;
        EvoAPI::CheckLoginResponse loginResponse;
        for (int i = 0; i < 10; ++i)
        {
            Sleep(1000);
            cout << "Checking ...  " << endl;
            LoginGood = CheckLogin(authenticateResponse.request_id, loginResponse);
            WriteBasicResponse(loginResponse);
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
            secure_string user, pw;
            if (GetCredsFromPayload(validateMfaResponse, user, pw))
            {
                cout << "user: " << user << endl << "pw:   " << pw << endl;
            }
            else
            {
                cout << "Failed to get creds" << endl;
            }
        }
    }
    else {
        cout << "Authenticate failed ..." << endl;
        cout << "Http response: " << authenticateResponse.httpStatus << ", message: " << authenticateResponse.raw_response <<  endl;
    }
}
