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
#include "../EvoCommon/EvoConsts.h"

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


static CharWidthExtLogFunc pCharWidthExtLogFunc = nullptr;
void EvoAPI::SetCharWidthExtLogFunc(CharWidthExtLogFunc pFunc)
{
    pCharWidthExtLogFunc = pFunc;
}

void DoTheLog(LPCSTR message, LPCSTR filename, int lineno)
{
#ifdef _DEBUG
    bool flag = false;
#else
    bool flag = true;
#endif

    if (pCharWidthExtLogFunc)
    {
        pCharWidthExtLogFunc(message, filename, lineno, flag);
    }
}

void DoTheLog(std::string message, LPCSTR filename, int lineno)
{
    DoTheLog(message.c_str(), filename, lineno);
}

#define __FILENAME__ (strrchr(__FILE__, '\\') ? strrchr(__FILE__, '\\') + 1 : __FILE__)
#define LogAlways(message) DoTheLog(message, __FILENAME__, __LINE__)


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

void EvoAPI::SetCustomPort(int port)
{
    m_nCustomPort = port;
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
        //LogPrint(LOG_DEBUG, "Setting access type to WINHTTP_ACCESS_TYPE_DEFAULT_PROXY");
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
        LogAlways("WinHttpOpen failure: " + to_string(GetLastError()));
        m_dwLastError = SETUP_ERROR;
        return evoApiResponse;
    }

    std::wstring sFullUrl = m_strBaseUrl + endpoint;

    ATL::CUrl url;
    url.CrackUrl(sFullUrl.c_str());

    CWinHttpHandle hConnect = WinHttpConnect(hSession, url.GetHostName(), m_nCustomPort != 0 ? m_nCustomPort : INTERNET_DEFAULT_HTTPS_PORT, NULL);

    if (!hConnect)
    {
        LogAlways("WinHttpConnect failure: " + to_string(GetLastError()));
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
        LogAlways("WinHttpOpenRequest failure: " + to_string(GetLastError()));
        m_dwLastError = SETUP_ERROR;
        return evoApiResponse;

    }

    DWORD dwReqOpts = 0;
    if (!WinHttpSetOption(hRequest, WINHTTP_OPTION_SECURITY_FLAGS, &dwReqOpts, sizeof(DWORD)))
    {
        LogAlways("WinHttpSetOptionRequest failure: " + to_string(GetLastError()));
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
                LogAlways("WinHttpSetOption for SSL flags failure: " + to_string(GetLastError()));
            m_dwLastError = SETUP_ERROR;
            return evoApiResponse;//ENDPOINT_ERROR_SETUP_ERROR;
        }
    }

    // Set timeouts on the request handle
    if (!HasDefaultTimeouts() && !WinHttpSetTimeouts(hRequest, m_nResolveTimeOut, m_nConnectTimeOut, m_nSendTimeOut, m_nReceiveTimeOut))
    {
        LogAlways("Failed to set timeouts on hRequest: " + to_string(GetLastError()));
    }

    LPCWSTR pwzAdditionalHeaders = L"Content-type: application/json\r\n";
    if (wstring(L"GET") == pwzMethod)
    {
        pwzAdditionalHeaders = WINHTTP_NO_ADDITIONAL_HEADERS;//  L"Content-type: application/x-www-form-urlencoded\r\n";
    }

    bResults = WinHttpSendRequest(hRequest, pwzAdditionalHeaders, (DWORD)-1, (LPVOID)data.c_str(), (DWORD)data.length(), (DWORD)data.length(), 0);

    if (!bResults)
    {
        LogAlways("WinHttpSendRequest failure: " + to_string(GetLastError()));
        m_dwLastError = SERVER_UNAVAILABLE;
        return evoApiResponse;
    }

    if (bResults)
    {
        bResults = WinHttpReceiveResponse(hRequest, NULL);
        if (!bResults)
        {
            LogAlways("Immediate failure WinHtpReceiveResponse");
        }

    }

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
                LogAlways("WinHttpQueryDataAvailable failure: " + to_string(GetLastError()));
                evoApiResponse.sResponse = ""; //ENDPOINT_ERROR_RESPONSE_ERROR;
            }

            pszOutBuffer = new char[ULONGLONG(dwSize) + 1];
            if (!pszOutBuffer)
            {
                LogAlways("WinHttpReadData out of memory: " + to_string(GetLastError()));
                evoApiResponse.sResponse = ""; // ENDPOINT_ERROR_RESPONSE_ERROR;
                dwSize = 0;
            }
            else
            {
                // Read the data.
                ZeroMemory(pszOutBuffer, (ULONGLONG)dwSize + 1);
                if (!WinHttpReadData(hRequest, (LPVOID)pszOutBuffer, dwSize, &dwDownloaded))
                {
                    LogAlways("WinHttpReadData error: " + to_string(GetLastError()));
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
        DWORD dwLastError = GetLastError();
        LogAlways("WinHttp Result error: " + to_string(dwLastError));
        evoApiResponse.sResponse = "";
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
    wsprintfA(szBuf, "{\"user\":\"%S\",\"password\":\"%S\",\"environment_url\":\"%S\",\"domain\":\"%S\"}", 
        wsUser.c_str(), wsPassword.c_str(), m_strEnvironmentUrl.c_str(), GetDomainOrMachineIncludingRegistry().c_str());

    auto evoApiResponse = Connect(L"authenticate", szBuf);
    response.assign(evoApiResponse);
    if (evoApiResponse.dwStatus != HTTP_STATUS_OK)
        return false;

    auto j = tryParse(evoApiResponse.sResponse);
    if (j == nullptr)
        return false;

    bool bRet = false;
    try {
        response.bMFAEnabled = j["mfa_enabled"];
        response.request_id = j["request_id"];
        bRet = true;
    }
    catch (...) {
        LogAlways("Missing elements in authenticate payload.");
    }

    return bRet;
}

static std::wstring s2ws(std::string s)
{
    using convert_typeX = std::codecvt_utf8<wchar_t>;
    std::wstring_convert<convert_typeX, wchar_t> converterX;

    return converterX.from_bytes(s);
}

bool EvoAPI::ValidateMFA(const std::wstring& wsMFACode, const std::wstring& wsUser, const std::wstring& wsPassword, ValidateMFAResponse& response)
{
    char szBuf[1024];
    wsprintfA(szBuf, "{ \"mfa_code\" : \"%S\", \"environment_url\" : \"%S\", \"user\" : \"%S\", \"password\" : \"%S\", \"domain\" : \"%S\"}",
        wsMFACode.c_str(), m_strEnvironmentUrl.c_str(), wsUser.c_str(), wsPassword.c_str(), GetDomainOrMachineIncludingRegistry().c_str());

    auto evoApiResponse = Connect(L"validate_mfa", szBuf);
    response.assign(evoApiResponse);

    if (evoApiResponse.dwStatus != HTTP_STATUS_OK)
        return false;

    auto j = tryParse(evoApiResponse.sResponse);
    if (j == nullptr)
        return false;

    bool bRet = false;
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
        bRet = true;
    }
    catch (...)
    {
        LogAlways("Missing elements in validate_mfa payload");
    }
    return bRet;
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

    bool bRet = false;
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
        bRet = true;
    }
    catch (...)
    {
        LogAlways("Missing elements in check_login_response payload");
    }
    return bRet;
}


std::wstring GetDomainOrMachineIncludingRegistry()
{
    DWORD bufSize = MAX_PATH;
    WCHAR domainNameBuf[MAX_PATH];

    static std::wstring wsRegisty = []()
    {
        WCHAR lambdaBuf[MAX_PATH] = L"";
        ULONG nBufSize = MAX_PATH;

        CRegKey regKey;
        if (ERROR_SUCCESS == regKey.Open(HKEY_LOCAL_MACHINE, REG_STRING_EVOBASE, KEY_READ))
        {
            regKey.QueryStringValue(L"Domain", lambdaBuf, &nBufSize);
            if (nBufSize > 1)
            {
                CString s{ lambdaBuf };
                lambdaBuf[0] = 0;

                s.Trim();
                if (!s.IsEmpty())
                {
                    wcscpy_s(lambdaBuf, s);
                    return wstring(lambdaBuf);
                }
            }
        }
        return wstring();
    } ();

    if (!wsRegisty.empty())
        return wsRegisty;

    std::wstring wsDomainName;
    GetComputerNameEx(ComputerNameDnsDomain, domainNameBuf, &bufSize);
    if (bufSize != 0)
        wsDomainName = domainNameBuf;

    if (bufSize == 0) {
        bufSize = MAX_PATH;
        GetComputerName(domainNameBuf, &bufSize);
        if (bufSize != 0)
            wsDomainName = domainNameBuf;
    }

    if (!wsDomainName.empty())
    {
        std::transform(wsDomainName.begin(), wsDomainName.end(), wsDomainName.begin(),
            [](wchar_t c) { return std::tolower(c); });

        return wsDomainName;
    }

    return L"";
}



bool EvoAPI::ValidateMFA90(const std::wstring& wsMFACode, const std::wstring& wsUser, ValidateMFA90Response& response)
{
    char szBuf[1024];
    wsprintfA(szBuf, "{ \"mfa_code\" : \"%S\", \"environment_url\" : \"%S\", \"user\" : \"%S\", \"desktop_mfa\" : \"true\", \"domain\" : \"%S\"}",
        wsMFACode.c_str(), m_strEnvironmentUrl.c_str(), wsUser.c_str(), GetDomainOrMachineIncludingRegistry().c_str());

    auto evoApiResponse = Connect(L"validate_mfa", szBuf);
    response.assign(evoApiResponse);

    if (evoApiResponse.dwStatus != HTTP_STATUS_OK)
        return false;


    auto j = tryParse(evoApiResponse.sResponse);
    if (j == nullptr)
        return false;

    bool bRet = false;
    try {
        bool bSuccess = j["success"];
        if (!bSuccess)
            return false;

        // there's an "offline_code" ... but what do do about it?
        response.offline_code = to_string(j["offline_code"]);

        bRet = true;
    }
    catch (...) {

    }

    return bRet;
}

bool EvoAPI::Authenticate90(const std::wstring& wsUser, AuthenticateResponse& response)
{
    char szBuf[2024];
    wsprintfA(szBuf, "{\"environment_url\":\"%S\",\"user\":\"%S\",\"domain\":\"%S\"}",
        m_strEnvironmentUrl.c_str(), wsUser.c_str(),  GetDomainOrMachineIncludingRegistry().c_str());

    auto evoApiResponse = Connect(L"send_push", szBuf);
    response.assign(evoApiResponse);

    if (evoApiResponse.dwStatus != HTTP_STATUS_OK)
        return false;


    auto j = tryParse(evoApiResponse.sResponse);
    if (j == nullptr)
        return false;

    bool bRet = false;
    try {
        response.bMFAEnabled = j["mfa_enabled"];
        response.request_id = j["request_id"];

        if (!response.bMFAEnabled)
            return false;

        bRet = true;
    }
    catch (...) {

    }

    return bRet;
}

bool EvoAPI::CheckLoginRequest(std::string request_id, CheckLogin90Response& response)
{
    WCHAR szBuf[1024];
    SecureZeroMemory(szBuf, sizeof(szBuf));
    wsprintf(szBuf, _T("check_login_request?request_id=%S"), request_id.c_str());

    auto connectResponse = Connect(szBuf, "", L"GET");
    response.assign(connectResponse);
    if (connectResponse.dwStatus != HTTP_STATUS_OK)
        return false;

    auto j = tryParse(connectResponse.sResponse);
    if (j == nullptr)
        return false;

    bool bRet = false;
    try {
        bool bSuccess = j["success"];
        if (!bSuccess)
            return false;

        response.offline_code = to_string(j["offline_code"]);
        bRet = true;
    }
    catch (...) {

    }

    return bRet;
}

