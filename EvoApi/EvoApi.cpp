// EvoApi.cpp : Defines the functions for the static library.
//

#include "pch.h"
#include "framework.h"
#include "EvoApi.h"
#include <winhttp.h>
#include <atlutil.h>
#include <iostream>
#include <codecvt>
#include "../EvoCredProvider/CoreLibs_/nlohmann/json.hpp"
using namespace std;

class CWinHttpHandle
{
public:
    CWinHttpHandle(HINTERNET h = 0)
        : m_hInternet(h)
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


nlohmann::json tryParse(const std::string& in)
{
    nlohmann::json j;
    try
    {
        j = nlohmann::json::parse(in);
        return j;
    }
    catch (const nlohmann::json::parse_error& /*err*/)
    {
        //DebugPrint(err.what());
        return nullptr;
    }
}


std::wstring EvoAPI::DefaultBaseUrl = L"https://api.evosecurity.com/api/v1/desktop/";
std::wstring EvoAPI::DefaultEnvironmentUrl = L"https://evo.evosecurity.io";

EvoAPI::EvoAPI(LPCWSTR pwzBaseUrl, LPCWSTR pwzEnvironmentUrl)
    : m_strBaseUrl(pwzBaseUrl != nullptr && *pwzBaseUrl != 0 ? pwzBaseUrl : DefaultBaseUrl.c_str())
    , m_strEnvironmentUrl(pwzEnvironmentUrl != nullptr && *pwzEnvironmentUrl != 0 ? pwzEnvironmentUrl : DefaultEnvironmentUrl.c_str())
{
}

EvoAPI::EvoAPI(EvoString baseUrl, EvoString environmentUrl)
    : EvoAPI(baseUrl.c_str(), environmentUrl.c_str()) // delegated constructor
{
}

void EvoAPI::DebugPrint(LPCSTR)
{
    // stubbed for nothing
}

void EvoAPI::ReleaseDebugPrint(const std::string& s)
{

}

#pragma warning(disable : 4996)

DWORD EvoAPI::GetDefaultAccessType()
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

EvoAPI::Response EvoAPI::Connect(EvoString endpoint, const std::string& data, LPCWSTR pwzMethod)
{
    Response evoApiResponse;

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

    bResults = WinHttpSendRequest(hRequest, pwzAdditionalHeaders, (DWORD)-1, (LPVOID)data.c_str(), (DWORD)data.length(), (DWORD)data.length(), 0);

    if (!bResults)
    {
        ReleaseDebugPrint("WinHttpSendRequest failure: " + to_string(GetLastError()));
        m_dwLastError = SERVER_UNAVAILABLE;
        return evoApiResponse;
    }

    if (bResults)
        bResults = WinHttpReceiveResponse(hRequest, NULL);

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
#if defined(_DEBUG) && FALSE
            if (bResults)
            {
                std::wcout << ws << endl;
            }
#endif

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

bool EvoAPI::Authenticate(const std::wstring& wsUser, const secure_wstring& wsPassword, AuthenticateResponse& response)
{
    char szBuf[2024];
    wsprintfA(szBuf, "{\"user\":\"%S\",\"password\":\"%S\",\"environment_url\":\"%S\"}", wsUser.c_str(), wsPassword.c_str(), m_strEnvironmentUrl.c_str());

    auto evoApiResponse = Connect(L"authenticate", szBuf);
    response.assign(evoApiResponse);
    if (evoApiResponse.dwStatus != HTTP_STATUS_OK)
        return false;

    auto j = tryParse(evoApiResponse.sResponse);
    if (j == nullptr)
        return false;

    response.bMFAEnabled = j["mfa_enabled"];
    response.request_id = j["request_id"];

    return true;
}

static std::wstring s2ws(std::string s)
{
    using convert_typeX = std::codecvt_utf8<wchar_t>;
    std::wstring_convert<convert_typeX, wchar_t> converterX;

    return converterX.from_bytes(s);
}

bool EvoAPI::ValidateMFA(const std::wstring& wsMFACode, const std::wstring& wsUser, const std::wstring& wsPassword, ValidateMFAResponse& response)
{
    char szBuf[2024];
    wsprintfA(szBuf, "{ \"mfa_code\" : \"%S\", \"environment_url\" : \"%S\", \"user\" : \"%S\", \"password\" : \"%S\"}",
        wsMFACode.c_str(), m_strEnvironmentUrl.c_str(), wsUser.c_str(), wsPassword.c_str());

    auto evoApiResponse = Connect(L"validate_mfa", szBuf);
    response.assign(evoApiResponse);

    if (evoApiResponse.dwStatus != HTTP_STATUS_OK)
        return false;

    auto j = tryParse(evoApiResponse.sResponse);
    if (j == nullptr)
        return false;

    try
    {
        response.success =  j["success"];
        response.offlineCode = j["offline_code"];
        response.iters = j["iter"];
        response.data = j["data"];
        response.iv = j["iv"];
        response.salt = j["salt"];
        response.cipher = j["cipher"];
        response.domain = s2ws(j["domain"]);
    }
    catch (...)
    {

    }
    return true;
}

bool EvoAPI::CheckLoginRequest(LPCSTR pwzCode, CheckLoginResponse& response)
{
    WCHAR szBuf[1024];
    SecureZeroMemory(szBuf, sizeof(szBuf));
    wsprintf(szBuf, _T("check_login_request?request_id=%S"), pwzCode);

    auto connectResponse = Connect(szBuf, "", L"GET");
    response.assign(connectResponse);
    if (connectResponse.dwStatus != HTTP_STATUS_OK)
        return false;

    auto j = tryParse(connectResponse.sResponse);
    if (j == nullptr)
        return false;

    try
    {
        response.success =  j["success"];
        response.offlineCode = j["offline_code"];
        response.iters = j["iter"];
        response.data = j["data"];
        response.iv = j["iv"];
        response.salt = j["salt"];
        response.cipher = j["cipher"];
        response.domain = s2ws(j["domain"]);
    }
    catch (...)
    {

    }
    return true;
}

void EvoAPI::SetCustomPort(int port)
{
    m_nCustomPort = port;
}


void TestJson()
{
    using namespace nlohmann;
    std::string s{ "{\"user\":\"evo.testing@evosecurity.com\",\"password\":\"Testing123!\",\"environment_url\":\"https://www.evosecurity.io\", \"whatevs\":1234}" };

    try
    {
        auto j = json::parse(s);

        string user = j["user"];
        string pw = j["password"];
        long whatevs = j["whatevs"];

    }
    catch (const json::parse_error& err) // for parser
    {
        cout << err.what() << endl;
    }
    catch (const json::exception& e) // for [] operator ...
    {
        cout << e.what() << endl;
    }
    catch (const std::exception& e)
    {
        cout << e.what();
    }
}
