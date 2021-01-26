/* * * * * * * * * * * * * * * * * * * * *
**
** Copyright 2019 NetKnights GmbH
** Author: Nils Behlen
**
**    Licensed under the Apache License, Version 2.0 (the "License");
**    you may not use this file except in compliance with the License.
**    You may obtain a copy of the License at
**
**        http://www.apache.org/licenses/LICENSE-2.0
**
**    Unless required by applicable law or agreed to in writing, software
**    distributed under the License is distributed on an "AS IS" BASIS,
**    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
**    See the License for the specific language governing permissions and
**    limitations under the License.
**
** * * * * * * * * * * * * * * * * * * */
#include "pch.h"
#include "Configuration.h"
#include "Utilities.h"
#include "version.h"
#include "Logger.h"
#include "RegistryReader.h"
#include "EvoConsts.h"
#include "EvoSolution.h"

using namespace std;
using namespace ATL;

const wstring Configuration::registryPath = REG_STRING_EVOBASE;
const wstring Configuration::registryRealmPath = REG_STRING_EVOREALM;

class CEvoRegKey : public CRegKey
{
public:
	CEvoRegKey(const wstring& keyName)
	{
		Open(HKEY_LOCAL_MACHINE, keyName.c_str(), KEY_READ);
	}
	bool Get(LPCWSTR value_name, wstring& wsOut)
	{
		WCHAR szBuf[MAX_PATH]; *szBuf = 0;
		ULONG nChars = MAX_PATH;
		if (m_hKey) QueryStringValue(value_name, szBuf, &nChars);
		wsOut = szBuf;
		return nChars > 0;
	}
	bool Get(LPCWSTR value_name, string& sOut)
	{
		wstring ws;
		if (!Get(value_name, ws))
			return false;

		DebugPrint(L"Before translation special key: " + ws);

		sOut = EvoSolution::ws2s(ws);
		return true;
	}

	bool Get(LPCWSTR value_name, int& i)
	{

		DWORD dw = 0;
		bool bRet = (m_hKey != 0 && ERROR_SUCCESS == QueryDWORDValue(value_name, dw));
		i = dw;
		return bRet;
	}

	bool Get(LPCWSTR value_name, bool& b)
	{
		DWORD dw = 0;
		bool bRet = (m_hKey != 0 && ERROR_SUCCESS == QueryDWORDValue(value_name, dw));
		b = (dw != 0);
		return bRet;
	}
};

Configuration::Configuration()
{
	CEvoRegKey rkey(registryPath);

	rkey.Get(L"v1_bitmap_path", bitmapPath);
	rkey.Get(L"hide_domainname", hideDomainName);
	rkey.Get(L"hide_fullname", hideFullName);
	rkey.Get(L"hide_otp_sleep_s", hide_otp_sleep_s);

	rkey.Get(L"two_step_hide_otp", twoStepHideOTP);
	rkey.Get(L"two_step_send_empty_password", twoStepSendEmptyPassword);
	rkey.Get(L"two_step_send_password", twoStepSendPassword);

	rkey.Get(L"log_sensitive", piconfig.logPasswords);
	rkey.Get(L"release_log", releaseLog);

	rkey.Get(L"show_domain_hint", showDomainHint);
	// Custom field texts: check if set, otherwise use defaults (from header)
	wstring tmp;
	rkey.Get(L"login_text", tmp);
	loginText = tmp.empty() ? L"EvoSecurity Login" : tmp;

	rkey.Get(L"otp_text", otpFieldText);

	rkey.Get(L"otp_fail_text", tmp);
	defaultOTPFailureText = tmp.empty() ? Utilities::GetTranslatedText(TEXT_WRONG_OTP) : tmp;

	rkey.Get(L"otp_hint_text", tmp);
	defaultOTPHintText = tmp.empty() ? Utilities::GetTranslatedText(TEXT_DEFAULT_OTP_HINT) : tmp;

	// Config for PrivacyIDEA
	rkey.Get(L"hostname", piconfig.hostname);
	// Check if the path contains the placeholder, if so replace with nothing
	rkey.Get(L"path", tmp);
	piconfig.path = (tmp == L"/path/to/pi" ? L"" : tmp);

	rkey.Get(L"ssl_ignore_unknown_ca", piconfig.ignoreUnknownCA);
	rkey.Get(L"ssl_ignore_invalid_cn", piconfig.ignoreInvalidCN);
	rkey.Get(L"custom_port", piconfig.customPort);
	rkey.Get(L"offline_file", piconfig.offlineFilePath);
	rkey.Get(L"offline_try_window", piconfig.offlineTryWindow);

	rkey.Get(L"resolve_timeout", piconfig.resolveTimeoutMS);
	rkey.Get(L"connect_timeout", piconfig.connectTimeoutMS);
	rkey.Get(L"send_timeout", piconfig.sendTimeoutMS);
	rkey.Get(L"receive_timeout", piconfig.receiveTimeoutMS);

	// format domain\username or computername\username
	rkey.Get(L"excluded_account", excludedAccount);

	rkey.Get(L"specialKey", specialKey);

	// Realm Mapping
	rkey.Get(L"default_realm", piconfig.defaultRealm);
	if (rkey) rkey.Close();

	RegistryReader rr(registryPath);
	if (!rr.getAll(registryRealmPath, piconfig.realmMap))
	{
		piconfig.realmMap.clear();
	}

	// Validate that only one of hideDomainName OR hideFullName is active
	// In the installer it is exclusive but could be changed in the registry
	if (hideDomainName && hideFullName)
	{
		hideDomainName = false;
	}
	// Validate 2Step
	if (twoStepSendEmptyPassword || twoStepSendPassword)
	{
		twoStepHideOTP = true;
	}
	if (twoStepSendEmptyPassword && twoStepSendPassword)
	{
		twoStepSendEmptyPassword = false;
	}

	// Get the Windows Version, deprecated
#pragma warning(disable:4996)
	OSVERSIONINFOEX info;
	ZeroMemory(&info, sizeof(OSVERSIONINFOEX));
	info.dwOSVersionInfoSize = sizeof(OSVERSIONINFOEX);
	GetVersionEx((LPOSVERSIONINFO)&info);

	winVerMajor = info.dwMajorVersion;
	winVerMinor = info.dwMinorVersion;
	winBuildNr = info.dwBuildNumber;
}

// for printing
inline wstring b2ws(bool b) {
	return b ? wstring(L"true") : wstring(L"false");
}

void Configuration::printConfiguration()
{
	DebugPrint("-----------------------------");
	DebugPrint("CP Version: " + string(VER_FILE_VERSION_STR));
	DebugPrint(L"Windows Version: " + to_wstring(winVerMajor) + L"." + to_wstring(winVerMinor)
		+ L"." + to_wstring(winBuildNr));
	DebugPrint("------- Configuration -------");
	DebugPrint(L"Hostname: " + piconfig.hostname);
	DebugPrint(L"Path: " + piconfig.path);
	DebugPrint(L"Custom port: " + to_wstring(piconfig.customPort));
	DebugPrint(L"Resolve timeout: " + to_wstring(piconfig.resolveTimeoutMS));
	DebugPrint(L"Connect timeout: " + to_wstring(piconfig.connectTimeoutMS));
	DebugPrint(L"Send timeout: " + to_wstring(piconfig.sendTimeoutMS));
	DebugPrint(L"Receive timeout: " + to_wstring(piconfig.receiveTimeoutMS));
	DebugPrint(L"Login text: " + loginText);
	DebugPrint(L"OTP field text: " + otpFieldText);
	DebugPrint(L"OTP failure text: " + defaultOTPFailureText);
	DebugPrint(L"Hide domain only: " + b2ws(hideDomainName));
	DebugPrint(L"Hide full name: " + b2ws(hideFullName));
	DebugPrint(L"SSL ignore invalid CN: " + b2ws(piconfig.ignoreUnknownCA));
	DebugPrint(L"SSL ignore invalid CN: " + b2ws(piconfig.ignoreInvalidCN));
	DebugPrint(L"2step hide OTP: " + b2ws(twoStepHideOTP));
	DebugPrint(L"2step send empty PW: " + b2ws(twoStepSendEmptyPassword));
	DebugPrint(L"2step send domain PW: " + b2ws(twoStepSendPassword));
	DebugPrint(L"Release Log: " + b2ws(releaseLog));
	DebugPrint(L"Log sensitive data: " + b2ws(piconfig.logPasswords));
	DebugPrint(L"No default: " + b2ws(noDefault));
	DebugPrint(L"Show domain hint: " + b2ws(showDomainHint));
	DebugPrint(L"Bitmap path: " + bitmapPath);
	DebugPrint(L"Offline file path: " + piconfig.offlineFilePath);
	DebugPrint(L"Offline try window: " + to_wstring(piconfig.offlineTryWindow));
	DebugPrint("Special key: " + specialKey);
	DebugPrint(L"EnvironmentUrl: " + environmentUrl);
	DebugPrint(L"Default realm: " + piconfig.defaultRealm);

	wstring tmp;
	for (const auto& item : piconfig.realmMap)
	{
		tmp += item.first + L"=" + item.second + L", ";
	}
	DebugPrint("Realm mapping:");
	DebugPrint(tmp.substr(0, tmp.size() - 2).c_str());

	DebugPrint("-----------------------------");
}