#pragma once

#include "../EvoCommon/EvoSecureString.h"

typedef void(*CharWidthExtLogFunc)(LPCSTR message, LPCSTR file, int lineNum, bool bRelease);

class EvoAPI
{
    using EvoString = std::wstring;
public:
    EvoAPI(LPCWSTR pwzBaseUrl = nullptr, LPCWSTR pwzEnvironmentUrl = nullptr); // if nullptr uses default
    EvoAPI(EvoString baseUrl, EvoString environmentUrl);

    enum ErrorType { NONE, SETUP_ERROR, SERVER_UNAVAILABLE, FINAL_ERROR_EMPTY };


    DWORD GetDefaultAccessType();

    struct Response
    {
        DWORD dwStatus = 0;
        std::string sResponse;
    };

    static std::wstring DefaultBaseUrl;
    static std::wstring DefaultEnvironmentUrl;

    Response Connect(EvoString endpoint, const std::string& data, LPCWSTR pwzMethod = L"POST");

    using ResponseString = std::string; // chance to replace with secure_string later ...

    // maybe convoluted? maybe extra layer not needed and just use Response?
    struct BasicResponse
    {
        DWORD httpStatus = 0;
        std::string raw_response;
        void assign(const Response& rhs)
        {
            httpStatus = rhs.dwStatus;
            raw_response = rhs.sResponse;
        }
        bool IsServerError() const;
    };

    struct AuthenticateResponse : public BasicResponse
    {
        bool bMFAEnabled;
        ResponseString request_id;
    };

    struct LoginResponse : public BasicResponse
    {
        bool success = false;
        int offlineCode = 0;
        ResponseString data;
        ResponseString salt;
        ResponseString iv;
        int iters = 0;
        ResponseString cipher;
        std::wstring domain;
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

    struct ValidateMFA90Response : BasicResponse
    {
        ResponseString offline_code;
    };

    struct CheckLogin90Response : BasicResponse
    {
        ResponseString offline_code;
    };

    bool Authenticate(const std::wstring& wsUser, const secure_wstring& wsPassword, AuthenticateResponse& authResponse );
    bool ValidateMFA(const std::wstring& wsMFACode, const std::wstring&  wsUser, const std::wstring& wsPassword, ValidateMFAResponse& validateResponse);
    bool CheckLoginRequest(LPCSTR pszCode, CheckLoginResponse& clResponse);


    bool ValidateMFA90(const std::wstring& wsMFACode, const std::wstring& wsUser, ValidateMFA90Response& response);
    bool Authenticate90(const std::wstring& wsUser, AuthenticateResponse& response);
    bool CheckLoginRequest(const std::string request_id, CheckLogin90Response& response);


    void SetCustomPort(int port);


    static void SetCharWidthExtLogFunc(CharWidthExtLogFunc pFunc);

    bool IsServerUnavailable() const;

protected:
    EvoString m_strBaseUrl;
    EvoString m_strEnvironmentUrl;

    EvoAPI::ErrorType m_dwLastError = EvoAPI::ErrorType::NONE;
    int m_nCustomPort = 0;
    bool m_bIgnoreUnknownCA = false;
    bool m_bIgnoreInvalidCN = false;

    // 4 default values according to documentation for WinHttpSetTimeout
    const int RESOLOVE_TIMEOUT = 0;
    const int CONNECT_TIMEOUT = 60000;
    const int SEND_TIMEOUT = 30000;
    const int RECEIVE_TIMEOUT = 30000;

    int m_nResolveTimeOut = RESOLOVE_TIMEOUT;

    // the next 3 values were multiplied by 100, probably should be 1000 because timeout values are in milliseconds
    int m_nConnectTimeOut = CONNECT_TIMEOUT; 
    int m_nSendTimeOut = SEND_TIMEOUT; 
    int m_nReceiveTimeOut = RECEIVE_TIMEOUT;

    bool HasDefaultTimeouts() const
    {
        return m_nResolveTimeOut != RESOLOVE_TIMEOUT || m_nConnectTimeOut != CONNECT_TIMEOUT || m_nSendTimeOut != SEND_TIMEOUT || m_nReceiveTimeOut != RECEIVE_TIMEOUT;
    }
};

std::wstring GetDomainOrMachineIncludingRegistry();
