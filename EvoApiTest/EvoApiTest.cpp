// EvoApiTest.cpp : This file contains the 'main' function. Program execution begins and ends there.
//
#include <windows.h>
#include <iostream>
#include <EvoApi.h>
#include <decrypt.h>
#include <atlbase.h>

#pragma warning(disable : 4996)

using namespace std;

WCHAR wszDefaultEnvironmentUrl[] = L"https://evo.evosecurity.io";

bool Authenticate( EvoAPI::AuthenticateResponse& response)
{
    EvoAPI EvoApi{};
    return EvoApi.Authenticate(L"evo.testing@evosecurity.com", L"Testing123!", wszDefaultEnvironmentUrl, response);
}

bool ValidateMFA(EvoAPI::ValidateMFAResponse& response)
{
    std::wstring sAuthCode;
    cout << "Enter auth code:  ";
    wcin >> sAuthCode;

    EvoAPI EvoApi{};
    return EvoApi.ValidateMFA(sAuthCode.c_str(), L"evo.testing@evosecurity.com", L"Testing123!", wszDefaultEnvironmentUrl, response);
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
    //std::string skey = "mvXcphkyhzAGYtFgtFtR5k7TVh9mk7PL";
    std:: string skey;
    ATL::CRegKey rkey;
    if (S_OK == rkey.Open(HKEY_LOCAL_MACHINE, L"SOFTWARE\\EvoSecurity\\EvoLogin-CP\\", KEY_READ))
    {
        WCHAR szBuf[MAX_PATH];
        ULONG ulRead = _countof(szBuf);
        rkey.QueryStringValue(L"specialKey", szBuf, &ulRead);

        skey = wstring_to_string(szBuf);
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

int main()
{
    EvoAPI::ValidateMFAResponse validateMfaResponse;
    if (ValidateMFA(validateMfaResponse)) {
        cout << "validate_mfa succeeded" << endl;

        secure_string user, pw;
        if (GetCredsFromPayload(validateMfaResponse, user, pw))
        {
            cout << "user: " << user << endl << "pw:   " << pw << endl;
        }
    }
    else {
        cout << "validate_mfa failed" << endl;
    }

    EvoAPI::AuthenticateResponse authenticateResponse;
    if (Authenticate(authenticateResponse) && !authenticateResponse.request_id.empty())
    {
        cout << "Authenticating: " << authenticateResponse.request_id << endl;

        bool LoginGood = false;
        EvoAPI::CheckLoginResponse loginResponse;
        for (int i = 0; i < 10; ++i)
        {
            Sleep(1000);
            cout << "Checking ...  ";
            if (LoginGood = CheckLogin(authenticateResponse.request_id, loginResponse))
            {
                cout << "\nChecked ok" << endl;
                break;
            }
        }

        if (LoginGood)
        {
            secure_string user, pw;
            if (GetCredsFromPayload(validateMfaResponse, user, pw))
            {
                cout << "user: " << user << endl << "pw:   " << pw << endl;
            }
        }
    }
}
