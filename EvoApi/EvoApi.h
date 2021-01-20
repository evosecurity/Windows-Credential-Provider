#pragma once

#include "../EvoCommon/EvoSecureString.h"

class EvoAPI
{
    using EvoString = std::wstring;
public:
    EvoAPI(LPCWSTR pwzBaseUrl = nullptr); // if nullptr uses default 

    enum ErrorType { NONE, SETUP_ERROR, SERVER_UNAVAILABLE };

    void DebugPrint(LPCSTR);

    void ReleaseDebugPrint(const std::string& s);

    DWORD GetDefaultAccessType();

    struct Response
    {
        DWORD dwStatus = 0;
        std::string sResponse;
    };

    static std::wstring DefaultBaseUrl;

    Response Connect(EvoString endpoint, const std::string& data, LPCWSTR pwzMethod = L"POST");

    using ResponseString = std::string; // chance to replace with secure_string later ...
    struct AuthenticateResponse
    {
        bool bMFAEnabled;
        ResponseString request_id;
    };

    struct LoginResponse
    {
        bool success = false;
        int offlineCode = 0;
        ResponseString data;
        ResponseString salt;
        ResponseString iv;
        int iters = 0;
        ResponseString cipher;
        void Clear()
        {
            data = salt = iv = cipher = "";
            iters = 0;
            offlineCode = 0;
        }
    };


    struct ValidateMFAResponse : LoginResponse
    {
    };

    struct CheckLoginResponse : LoginResponse
    {
    };

    bool Authenticate(const std::wstring& wsUser, const secure_wstring& wsPassword, const std::wstring& wsEnvironmentUrl, AuthenticateResponse& authResponse );
    bool ValidateMFA(const std::wstring& wsMFACode, const std::wstring&  wsUser, const std::wstring& wsPassword, const std::wstring& wsEnvironmentUrl, ValidateMFAResponse& validateResponse);
    bool CheckLoginRequest(LPCSTR pszCode, CheckLoginResponse& clResponse);


    void SetCustomPort(int port);

protected:
    EvoString m_strBaseUrl;

    EvoAPI::ErrorType m_dwLastError = EvoAPI::ErrorType::NONE;
    int m_nCustomPort = 0;
    bool m_bIgnoreUnknownCA = false;
    bool m_bIgnoreInvalidCN = false;
    int m_nResolveTimeOut = 0;
    int m_nConnectTimeOut = 60;
    int m_nSendTimeOut = 30;
    int m_nReceiveTimeOut = 30;
};
