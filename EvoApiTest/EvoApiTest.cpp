// EvoApiTest.cpp : This file contains the 'main' function. Program execution begins and ends there.
//
#include <windows.h>
#include <iostream>
#include <EvoApi.h>
#include <decrypt.h>

#pragma warning(disable : 4996)

using namespace std;

#if 0
#define EVO_AUTHENTICATE_API L"authenticate"
#define EVO_VALIDATEMFA_API L"validate_mfa"
#define EVO_CHECKLOGINREQUEST_API L"check_login_request"


class CWinHttpHandle
{
public:
    CWinHttpHandle(HINTERNET h = 0)
        : m_hInternet (h)
    {

    }
    ~CWinHttpHandle()
    {
        Free();
    }

    operator bool()
    {
        return m_hInternet != nullptr;
    }

    operator HINTERNET ()
    {
        return m_hInternet;
    }

    void Free()
    {
        if (m_hInternet)
        {
            WinHttpCloseHandle(m_hInternet);
            m_hInternet = nullptr;
        }
    }

    CWinHttpHandle(CWinHttpHandle&) = delete;
    const CWinHttpHandle& operator=(CWinHttpHandle&) = delete;
    const CWinHttpHandle& operator=(HINTERNET h)
    {
        Free();
        m_hInternet = h;

    }

protected:
    HINTERNET m_hInternet;
};

class EvoAPI
{
    typedef std::wstring EvoString;
public:
    EvoAPI(LPCWSTR pwzBaseUrl)
        : m_strBaseUrl(pwzBaseUrl)
    {

    }

    nlohmann::json tryParse(const std::string& in)
    {
        nlohmann::json j;
        try
        {
            j = nlohmann::json::parse(in);
            return j;
        }
        catch (const nlohmann::json::parse_error& err)
        {
            DebugPrint(err.what());
            return nullptr;
        }
    }

    enum ErrorType { NONE, SETUP_ERROR , SERVER_UNAVAILABLE};

    void DebugPrint(LPCSTR)
    {
        // stubbed for nothing
    }

    void ReleaseDebugPrint(const std::string& s )
    {

    }

    DWORD GetDefaultAccessType()
    {
        DWORD dwAccessType = WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY;
        
        OSVERSIONINFOEX info;
        ZeroMemory(&info, sizeof(OSVERSIONINFOEX));
        info.dwOSVersionInfoSize = sizeof(OSVERSIONINFOEX);
        GetVersionEx((LPOSVERSIONINFO)&info);

        if (info.dwMajorVersion == 6 && info.dwMinorVersion <= 2)
        {
            dwAccessType = WINHTTP_ACCESS_TYPE_DEFAULT_PROXY;
            DebugPrint("Setting access type to WINHTTP_ACCESS_TYPE_DEFAULT_PROXY");
        }
        return dwAccessType;
    }

    struct EvoApiResponse
    {
        DWORD dwStatus = 0;
        std::string sResponse;
    };

    EvoApiResponse Connect(EvoString endpoint, const std::string& data, LPCWSTR pwzMethod = L"POST")
    {
        EvoApiResponse evoApiResponse;

        DWORD dwSize = 0;
        DWORD dwDownloaded = 0;
        LPSTR pszOutBuffer = nullptr;
        BOOL  bResults = FALSE;

        CWinHttpHandle hSession = WinHttpOpen(L"EvoSecurity", GetDefaultAccessType(), WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);

        if (!hSession)
        {
            ReleaseDebugPrint("WinHttpOpen failure: " + to_string(GetLastError()));
            m_dwLastError = SETUP_ERROR;
            return evoApiResponse;
        }

        std::wstring sFullUrl = m_strBaseUrl + endpoint;

        ATL::CUrl url;
        url.CrackUrl(sFullUrl.c_str());

        CWinHttpHandle hConnect = WinHttpConnect(hSession, url.GetHostName(), m_nCustomPort != 0 ? m_nCustomPort : INTERNET_DEFAULT_HTTPS_PORT, NULL);

        if (!hConnect)
        {
            ReleaseDebugPrint("WinHttpConnect failure: " + to_string(GetLastError()));
            m_dwLastError = SETUP_ERROR;
            return evoApiResponse;
        }

        std::wstring UrlPath = url.GetUrlPath();
        if (std::wstring(L"GET") == pwzMethod)
        {
            UrlPath += url.GetExtraInfo();
        }

        CWinHttpHandle hRequest = WinHttpOpenRequest(hConnect, pwzMethod, UrlPath.c_str(), NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_SECURE);

        if (!hRequest)
        {
            ReleaseDebugPrint("WinHttpOpenRequest failure: " + to_string(GetLastError()));
            m_dwLastError = SETUP_ERROR;
            return evoApiResponse;

        }

        DWORD dwReqOpts = 0;
        if (!WinHttpSetOption(hRequest, WINHTTP_OPTION_SECURITY_FLAGS, &dwReqOpts, sizeof(DWORD)))
        {
            ReleaseDebugPrint("WinHttpOpenRequest failure: " + to_string(GetLastError()));
            m_dwLastError = SETUP_ERROR;
            return evoApiResponse;//ENDPOINT_ERROR_SETUP_ERROR;
        }

        /////////// SET THE FLAGS TO IGNORE SSL ERRORS, IF SPECIFIED /////////////////
        DWORD dwSSLFlags = 0;
        if (m_bIgnoreUnknownCA) {
            dwSSLFlags = SECURITY_FLAG_IGNORE_UNKNOWN_CA;
            //DebugPrintLn("SSL ignore unknown CA flag set");
        }

        if (m_bIgnoreInvalidCN) {
            dwSSLFlags = dwSSLFlags | SECURITY_FLAG_IGNORE_CERT_CN_INVALID;
            //DebugPrintLn("SSL ignore invalid CN flag set");
        }

        if (m_bIgnoreUnknownCA || m_bIgnoreInvalidCN) {
            if (!WinHttpSetOption(hRequest, WINHTTP_OPTION_SECURITY_FLAGS, &dwSSLFlags, sizeof(DWORD))) {
                ReleaseDebugPrint("WinHttpSetOption for SSL flags failure: " + to_string(GetLastError()));
                m_dwLastError = SETUP_ERROR;
                return evoApiResponse;//ENDPOINT_ERROR_SETUP_ERROR;
            }
        }

        // Set timeouts on the request handle
        if (!WinHttpSetTimeouts(hRequest, m_nResolveTimeOut, m_nConnectTimeOut, m_nSendTimeOut, m_nReceiveTimeOut))
        {
            ReleaseDebugPrint("Failed to set timeouts on hRequest: " + to_string(GetLastError()));
            // Continue with defaults
        }

        LPCWSTR pwzAdditionalHeaders = L"Content-type: application/json\r\n";
        if (wstring(L"GET") == pwzMethod)
        {
            pwzAdditionalHeaders = WINHTTP_NO_ADDITIONAL_HEADERS;//  L"Content-type: application/x-www-form-urlencoded\r\n";
        }

        bResults = WinHttpSendRequest(hRequest, pwzAdditionalHeaders, (DWORD)-1, (LPVOID)data.c_str(), (DWORD) data.length(), (DWORD) data.length(), 0);

        if (!bResults)
        {
            ReleaseDebugPrint("WinHttpSendRequest failure: " + to_string(GetLastError()));
            m_dwLastError = SERVER_UNAVAILABLE;
            return evoApiResponse;
        }

        if (bResults)
            bResults = WinHttpReceiveResponse(hRequest, NULL);

        //string response;

        if (bResults)
        {
            DWORD dwHeaderSize = 0;
            WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_RAW_HEADERS_CRLF, WINHTTP_HEADER_NAME_BY_INDEX, NULL, &dwHeaderSize, WINHTTP_NO_HEADER_INDEX);
            if (GetLastError() == ERROR_INSUFFICIENT_BUFFER)
            {
                std::wstring ws;
                ws.resize(dwHeaderSize);
                bResults = WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_RAW_HEADERS_CRLF, WINHTTP_HEADER_NAME_BY_INDEX, 
                    &ws.front(), &dwHeaderSize, WINHTTP_NO_HEADER_INDEX);
                if (bResults)
                {
                    std::wcout << ws << endl;
                }

                DWORD dwSizeStatusCode = sizeof(&evoApiResponse.dwStatus);
                WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER, WINHTTP_HEADER_NAME_BY_INDEX,
                    &evoApiResponse.dwStatus, &dwSizeStatusCode, WINHTTP_NO_HEADER_INDEX);
            }

            dwSize;
            do
            {
                dwSize = 0;

                if (!WinHttpQueryDataAvailable(hRequest, &dwSize)) {
                    ReleaseDebugPrint("WinHttpQueryDataAvailable failure: " + to_string(GetLastError()));
                    evoApiResponse.sResponse = ""; //ENDPOINT_ERROR_RESPONSE_ERROR;
                }

                pszOutBuffer = new char[ULONGLONG(dwSize) + 1];
                if (!pszOutBuffer)
                {
                    ReleaseDebugPrint("WinHttpReadData out of memory: " + to_string(GetLastError()));
                    evoApiResponse.sResponse = ""; // ENDPOINT_ERROR_RESPONSE_ERROR;
                    dwSize = 0;
                }
                else
                {
                    // Read the data.
                    ZeroMemory(pszOutBuffer, (ULONGLONG)dwSize + 1);
                    if (!WinHttpReadData(hRequest, (LPVOID)pszOutBuffer, dwSize, &dwDownloaded))
                    {
                        ReleaseDebugPrint("WinHttpReadData error: " + to_string(GetLastError()));
                        evoApiResponse.sResponse = "";// ENDPOINT_ERROR_RESPONSE_ERROR;
                    }
                    else
                    {
                        evoApiResponse.sResponse = evoApiResponse.sResponse + string(pszOutBuffer);
                    }
                    // Free the memory allocated to the buffer.
                    delete[] pszOutBuffer;
                }

            } while (dwSize > 0);
        }

        if (!bResults)
        {
            ReleaseDebugPrint("WinHttp Result error: " + to_string(GetLastError()));
            evoApiResponse.sResponse = "";// ENDPOINT_ERROR_RESPONSE_ERROR;
        }

        if (evoApiResponse.sResponse.empty())
        {
            m_dwLastError = SERVER_UNAVAILABLE;
        }

        return evoApiResponse;
    }

    bool Authenticate(LPCWSTR pwzUser, LPCWSTR pwzPassword, LPCWSTR pwzEnvrironmentUrl)
    {
        char szBuf[2024];
        wsprintfA(szBuf, "{\"user\":\"%S\",\"password\":\"%S\",\"environment_url\":\"%S\"}", pwzUser, pwzPassword, pwzEnvrironmentUrl);

        auto evoApiResponse = Connect(L"authenticate", szBuf);

        auto j = tryParse(evoApiResponse.sResponse);
        if (j == nullptr)
            return false;

        bool bMFAEnabled = j["mfa_enabled"];
        std::string request_id = j["request_id"];

        return true;
    }

    bool ValidateMFA(LPCWSTR pwzMFACode, LPCWSTR pwzUser, LPCWSTR pwzPassword, LPCWSTR pwzEnvironmentUrl)
    {
        char szBuf[2024];
        wsprintfA(szBuf, "{ \"mfa_code\" : \"%S\", \"environment_url\" : \"%S\", \"user\" : \"%S\", \"password\" : \"%S\"}", 
            pwzMFACode, pwzEnvironmentUrl, pwzUser, pwzPassword);

        auto evoApiResponse = Connect(L"validate_mfa", szBuf);

        if (evoApiResponse.dwStatus != 200)
            return false;

        auto j = tryParse(evoApiResponse.sResponse);
        if (j == nullptr)
            return false;

        bool bSuccess = j["success"];
        string sOfflineCode = bSuccess ? to_string(j["offline_code"]) : string(); 

        return sOfflineCode.length() > 0;
    }

    bool CheckLoginRequest(LPCWSTR pwzCode)
    {
        TCHAR szBuf[1024];
        wsprintf(szBuf, _T("check_login_request?request_id=%s"), pwzCode);

        char cBuf[1024];
        wsprintfA(cBuf, "?request_id=%S", pwzCode);
        auto response = Connect(szBuf, "", L"GET");
        auto j = tryParse(response.sResponse);
        if (j == nullptr)
            return false;

        auto it = j.find("success");
        if (it != j.end())
        {
            auto c = it.value();
            if (c)
            {

            }
        }

        it = j.find("offline_code");
        string sOfflineCode;
        if (it != j.end())
        {
            sOfflineCode = std::to_string((long) it.value());
        }
        
        return sOfflineCode.length() > 0;
    }

    int SetCustomPort(int port)
    {
        m_nCustomPort = port;
    }

protected:
    EvoString m_strBaseUrl;

    ErrorType m_dwLastError = ErrorType::NONE;
    int m_nCustomPort = 0;
    bool m_bIgnoreUnknownCA = false;
    bool m_bIgnoreInvalidCN = false;
    int m_nResolveTimeOut = 0;
    int m_nConnectTimeOut = 60;
    int m_nSendTimeOut = 30;
    int m_nReceiveTimeOut = 30;
};

#endif

WCHAR wszDefaultEnvironmentUrl[] = L"https://evo.evosecurity.io";

bool Authenticate( EvoAPI::AuthenticateResponse& response)
{
    EvoAPI EvoApi{};
    return EvoApi.Authenticate(L"evo.testing@evosecurity.com", L"Testing123!", wszDefaultEnvironmentUrl, response);
}

void ValidateMFA()
{
    std::wstring sAuthCode;
    cout << "Enter auth code:  ";
    wcin >> sAuthCode;

    EvoAPI::ValidateMFAResponse response;
    EvoAPI EvoApi{};
    EvoApi.ValidateMFA(sAuthCode.c_str(), L"evo.testing@evosecurity.com", L"Testing123!", wszDefaultEnvironmentUrl, response);
}

//void CheckLogin()
//{
//    std::string sRequestId;
//    cout << "Enter request ID: ";
//    cin >> sRequestId;
//    if (sRequestId.length() > 0)
//    {
//        EvoAPI EvoApi;
//        EvoApi.CheckLoginRequest(sRequestId.c_str());
//    }
//}

bool CheckLogin(std::string request_id, EvoAPI::CheckLoginResponse& response)
{
    EvoAPI evoapi;
    return evoapi.CheckLoginRequest(request_id.c_str(), response);
}


extern void TestJson();

int main()
{

    ValidateMFA();

    EvoAPI::AuthenticateResponse authenticateResponse;
    if (Authenticate(authenticateResponse) && !authenticateResponse.request_id.empty())
    {

        bool LoginGood = false;
        EvoAPI::CheckLoginResponse loginResponse;
        for (int i = 0; i < 10; ++i)
        {
            if (LoginGood = CheckLogin(authenticateResponse.request_id, loginResponse))
                break;
            Sleep(1000);
        }

        if (LoginGood)
        {
            std::string skey = "mvXcphkyhzAGYtFgtFtR5k7TVh9mk7PL";
            secure_string sData = RubyDecode(loginResponse.data, loginResponse.salt, loginResponse.iv, skey);

            size_t find = sData.find(',');

            secure_string user = sData.substr(0, find);
            secure_string pw = sData.substr(find + 1);
        }
    }
    //CheckLogin();
    //TestJson();
}
