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

#pragma once
#include "EvoConf.h"
#include "Challenge.h"
#include "EvoSecureString.h"
#include <credentialprovider.h>
#include <mutex>
#include <shared_mutex>
#include <thread>

class Configuration
{
public:

	static const std::wstring registryPath;// = L"SOFTWARE\\Netknights GmbH\\PrivacyIDEA-CP\\";
	static const std::wstring registryRealmPath;// = registryPath + L"realm-mapping";

	Configuration();

	void printConfiguration();
	void MakeBaseUrl();

	PICONFIG piconfig;

	std::wstring loginText = L"";
	std::wstring otpFieldText = L"";
	std::wstring bitmapPath = L"";

	bool twoStepHideOTP = true;
	bool twoStepSendPassword = false;
	bool twoStepSendEmptyPassword = false;
	bool isSecondStep = false;

	bool hideFullName = false;
	bool hideDomainName = false;

	bool showDomainHint = false;

	bool releaseLog = false;

	bool noDefault = false;

	int hide_otp_sleep_s = 0;

	int winVerMajor = 0;
	int winVerMinor = 0;
	int winBuildNr = 0;

	bool pushAuthenticationSuccessful = false;

	bool isRemoteSession = false;

	bool doAutoLogon = false;

	bool userCanceled = false;

	Challenge challenge;
	std::wstring defaultOTPFailureText = L"";
	std::wstring defaultOTPHintText = L"";

	std::wstring failSafeUser = L"";

	bool clearFields = true;
	bool bypassPrivacyIDEA = false;

	std::string specialKey;
	std::wstring environmentUrl = L"https://evo.evosecurity.io";

	std::wstring baseUrl;
	bool m_bTenPercent;
	bool IsFirstStep() const { return !isSecondStep; }
	bool IsSecondStep() const { return isSecondStep; }
	void ClearSuccessFlags();
	void SetSuccessFlags();


	struct PROVIDER_
	{
		ICredentialProviderEvents* pCredentialProviderEvents = nullptr;
		UINT_PTR upAdviseContext = 0;

		CREDENTIAL_PROVIDER_USAGE_SCENARIO cpu = CPUS_INVALID;
		DWORD credPackFlags = 0;

		// Possibly read-write
		CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE* pcpgsr = nullptr;
		CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION* pcpcs = nullptr;
		PWSTR* status_text = nullptr;
		CREDENTIAL_PROVIDER_STATUS_ICON* status_icon = nullptr;
		ATL::CComPtr<ICredentialProviderCredentialEvents> pCredProvCredentialEvents;

		// Read-only
		ICredentialProviderCredential* pCredProvCredential = nullptr;
		wchar_t** field_strings = nullptr;
	} provider;

	struct CREDENTIAL
	{
		std::wstring username = L"";
		std::wstring domain = L"";
		SecureWString password = L"";
		std::wstring otp = L"";

		bool passwordMustChange = false;
		bool passwordChanged = false;

		// ChangePassword
		SecureWString newPassword1 = L"";
		SecureWString newPassword2 = L"";

		// these items are from EVO passing back 
		SecureWString validatedUsername;
		SecureWString validatedPassword;
		std::wstring validatedDomain;

	} credential;

	void SetLastOfflineCode(std::string sMfa);
	std::string GetLastOfflineCode() const;

	void SetMapValue(std::string name, std::string mfa);
	std::string GetMapValue(std::string name) const;
	std::string GetMapValue(std::wstring name) const;
	std::map<std::string, std::string> GetOfflineCodesMap();
	bool IsSystemAccount() const { return bSystemAccount; }
	std::string GetStoredOTP();

	enum OperatingMode {TEN_PERCENT_MODE = 10, NINETY_PERCENT_MODE = 90, FULL_MODE = 100};

	bool IsFullMode() const { return m_nMode == FULL_MODE; }
	bool IsNinetyMode() const { return m_nMode == NINETY_PERCENT_MODE; }
	bool IsTenMode() const { return m_nMode == TEN_PERCENT_MODE; }

private:
	mutable std::shared_mutex offlineCodeMutex;
	std::map<std::string, std::string> offlineCodeMap;
	std::string lastOfflineCode;
	bool bSystemAccount;

	int m_nMode = NINETY_PERCENT_MODE;

};

BOOL IsLocalSystem();
