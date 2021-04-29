#include "pch.h"

#include <EvoApi.h>
#include <decrypt.h>
#include "EvoCredential.h"
#include "Logger.h"
#include "helpers.h"
#include "EvoSolution.h"
#include "EvoCodes.h"
#include "resource.h"
#include <sstream>
#include <thread>
#include <future>
#include <comdef.h>
#include "EvoConsts.h"
#include "DataProtectHelper.h"
#include <winhttp.h>

using namespace std;


void LogHookFunc(LPCSTR message, LPCSTR lpszFile, int lineno, bool flag)
{
	Logger::Get().log(message, lpszFile, lineno, flag);
}

void InitApiLogging()
{
	static bool bInitedApiLogging = false;
	if (!bInitedApiLogging)
	{
		bInitedApiLogging = true;
		EvoAPI::SetCharWidthExtLogFunc(LogHookFunc);
	}
}

HRESULT CEvoCredential::CreateCredential(std::shared_ptr<Configuration> pConfig, CEvoCredential** ppCred)
{
	HRESULT hr;
	CComObject<CEvoCredential>* pCred = NULL;
	if (FAILED(hr = CComObject<CEvoCredential>::CreateInstance(&pCred)))
		return hr;

	InitApiLogging();

	pCred->SetConfiguration(pConfig);

	pCred->AddRef();
	*ppCred = pCred;
	return hr;
}


CEvoCredential::CEvoCredential()
{
	ZERO(_rgCredProvFieldDescriptors);
	ZERO(_rgFieldStatePairs);
	ZERO(_rgFieldStrings);
}

CEvoCredential::~CEvoCredential()
{
	_util.Clear(_rgFieldStrings, _rgCredProvFieldDescriptors, this, NULL, CLEAR_FIELDS_ALL_DESTROY);
}

HRESULT CEvoCredential::Initialize(__in const CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR* rgcpfd,
	__in const FIELD_STATE_PAIR* rgfsp,
	__in_opt PWSTR user_name,
	__in_opt PWSTR domain_name,
	__in_opt PWSTR password
)
{
	wstring wstrUsername, wstrDomainname;
	SecureWString wstrPassword;

	if (NOT_EMPTY(user_name))
	{
		//if (!m_config->m_bTenPercent)
			wstrUsername = wstring(user_name);
	}
	if (NOT_EMPTY(domain_name))
	{
		wstrDomainname = wstring(domain_name);
	}
	if (NOT_EMPTY(password))
	{
		wstrPassword = SecureWString(password);
	}
#ifdef _DEBUG
	DebugPrint(__FUNCTION__);
	DebugPrint(L"Username from provider: " + (wstrUsername.empty() ? L"empty" : wstrUsername));
	DebugPrint(L"Domain from provider: " + (wstrDomainname.empty() ? L"empty" : wstrDomainname));
	if (m_config->piconfig.logPasswords)
	{
		DebugPrint(L"Password from provider: " + (wstrPassword.empty() ? L"empty" : wstrPassword));
	}
#endif
	HRESULT hr = S_OK;

	if (!wstrUsername.empty())
	{
		DebugPrint("Copying user to credential");
		m_config->credential.username = wstrUsername;
	}

	if (!wstrDomainname.empty())
	{
		DebugPrint("Copying domain to credential");
		m_config->credential.domain = wstrDomainname;
	}

	if (!wstrPassword.empty())
	{
		DebugPrint("Copying password to credential");
		m_config->credential.password = wstrPassword;
		SecureZeroMemory(password, sizeof(password));
	}

	for (DWORD i = 0; SUCCEEDED(hr) && i < FID_NUM_FIELDS; i++)
	{
		//DebugPrintLn("Copy field #:");
		//DebugPrintLn(i + 1);
		_rgFieldStatePairs[i] = rgfsp[i];
		hr = FieldDescriptorCopy(rgcpfd[i], &_rgCredProvFieldDescriptors[i]);

		if (FAILED(hr))
		{
			break;
		}

		_util.InitializeField(_rgFieldStrings, i);
	}

	DebugPrint("Init result:");
	if (SUCCEEDED(hr))
	{
		DebugPrint("OK");
	}
	else
	{
		DebugPrint("FAIL");
	}

	return hr;
}

HRESULT CEvoCredential::Advise(ICredentialProviderCredentialEvents* pcpe)
{
	m_pCredProvCredentialEvents = pcpe;
	return S_OK;
}

HRESULT CEvoCredential::UnAdvise()
{
	m_pCredProvCredentialEvents.Release();
	return S_OK;
}

HRESULT CEvoCredential::SetSelected(BOOL* pbAutoLogon)
{
	DebugPrint(__FUNCTION__);
	*pbAutoLogon = false;
	HRESULT hr = S_OK;

	if (m_config->doAutoLogon)
	{
		*pbAutoLogon = TRUE;
		m_config->doAutoLogon = false;
	}

	if (m_config->credential.passwordMustChange
		&& m_config->provider.cpu == CPUS_UNLOCK_WORKSTATION
		&& m_config->winVerMajor != 10)
	{
		// We cant handle a password change while the maschine is locked, so we guide the user to sign out and in again like windows does
		DebugPrint("Password must change in CPUS_UNLOCK_WORKSTATION");
		ReleaseDebugPrint("Password must change in CPUS_UNLOCK_WORKSTATION");
		m_pCredProvCredentialEvents->SetFieldString(this, FID_LARGE_TEXT, L"Go back until you are asked to sign in.");
		m_pCredProvCredentialEvents->SetFieldString(this, FID_SMALL_TEXT, L"To change your password sign out and in again.");
		m_pCredProvCredentialEvents->SetFieldState(this, FID_LDAP_PASS, CPFS_HIDDEN);
		m_pCredProvCredentialEvents->SetFieldState(this, FID_OTP, CPFS_HIDDEN);
	}

	if (m_config->credential.passwordMustChange)
	{
		_util.SetScenario(this, m_pCredProvCredentialEvents, SCENARIO::CHANGE_PASSWORD);
		if (m_config->provider.cpu == CPUS_UNLOCK_WORKSTATION)
		{
			m_config->bypassPrivacyIDEA = true;
		}
	}

	if (m_config->credential.passwordChanged)
	{
		*pbAutoLogon = TRUE;
	}

	return hr;
}

HRESULT CEvoCredential::SetDeselected()
{
	DebugPrint(__FUNCTION__);

	HRESULT hr = S_OK;

	_util.Clear(_rgFieldStrings, _rgCredProvFieldDescriptors, this, m_pCredProvCredentialEvents, CLEAR_FIELDS_EDIT_AND_CRYPT);

	_util.ResetScenario(this, m_pCredProvCredentialEvents);

	// Reset password changing in case another user wants to log in
	m_config->credential.passwordChanged = false;
	m_config->credential.passwordMustChange = false;

	return hr;
}

HRESULT CEvoCredential::GetFieldState(__in DWORD dwFieldID,
	__out CREDENTIAL_PROVIDER_FIELD_STATE* pcpfs,
	__out CREDENTIAL_PROVIDER_FIELD_INTERACTIVE_STATE* pcpfis)
{
	//DebugPrintLn(__FUNCTION__);

	HRESULT hr = S_OK;

	// Validate paramters.
	if (dwFieldID < FID_NUM_FIELDS && pcpfs && pcpfis)
	{
		*pcpfs = _rgFieldStatePairs[dwFieldID].cpfs;
		*pcpfis = _rgFieldStatePairs[dwFieldID].cpfis;
		hr = S_OK;
	}
	else
	{
		hr = E_INVALIDARG;
	}

	//DebugPrintLn(hr);

	return hr;
}

HRESULT CEvoCredential::GetStringValue(DWORD dwFieldID, PWSTR* ppwsz)
{
	//DebugPrintLn(__FUNCTION__);

	HRESULT hr = S_OK;

	// Check to make sure dwFieldID is a legitimate index.
	if (dwFieldID < FID_NUM_FIELDS && ppwsz)
	{
		// Make a copy of the string and return that. The caller
		// is responsible for freeing it.
		hr = SHStrDupW(_rgFieldStrings[dwFieldID], ppwsz);
	}
	else
	{
		hr = E_INVALIDARG;
	}

	//DebugPrintLn(hr);

	return hr;
}

HRESULT CEvoCredential::GetBitmapValue(DWORD dwFieldID, HBITMAP* phbmp)
{
	DebugPrint(__FUNCTION__);

	HRESULT hr = E_INVALIDARG;
	if ((FID_LOGO == dwFieldID) && phbmp)
	{
		HBITMAP hbmp = nullptr;
		LPCTSTR lpszBitmapPath = m_config->bitmapPath.c_str();
		DebugPrint(lpszBitmapPath);

		if (NOT_EMPTY(lpszBitmapPath))
		{
			DWORD const dwAttrib = GetFileAttributes(lpszBitmapPath);

			DebugPrint(dwAttrib);

			if (dwAttrib != INVALID_FILE_ATTRIBUTES
				&& !(dwAttrib & FILE_ATTRIBUTE_DIRECTORY))
			{
				hbmp = (HBITMAP)LoadImage(nullptr, lpszBitmapPath, IMAGE_BITMAP, 0, 0, LR_LOADFROMFILE|LR_LOADTRANSPARENT);

				if (hbmp == nullptr)
				{
					DebugPrint(L"Error loading image: " + m_config->bitmapPath);
					DebugPrint(GetLastError());
				}
				else
				{
					DebugPrint(wstring(L"Using loaded image: ") + m_config->bitmapPath);
				}
			}
			else DebugPrint("Something invalid");
		}

		if (hbmp == nullptr)
		{
			DebugPrint("Loading alternate bitmap");
			hbmp = LoadBitmap(_AtlBaseModule.GetModuleInstance(), MAKEINTRESOURCE(IDB_NEW_TILE));
		}

		if (hbmp != nullptr)
		{
			hr = S_OK;
			*phbmp = hbmp;
		}
		else
		{
			hr = HRESULT_FROM_WIN32(GetLastError());
		}
	}
	else
	{
		hr = E_INVALIDARG;
	}

	DebugPrint(hr);

	return hr;
}

HRESULT CEvoCredential::GetSubmitButtonValue(DWORD dwFieldID, DWORD* pdwAdjacentTo)
{
	DebugPrint(__FUNCTION__);
	//DebugPrint("Submit Button ID:" + to_string(dwFieldID));
	if (FID_SUBMIT_BUTTON == dwFieldID && pdwAdjacentTo)
	{
		// This is only called once when the credential is created.
		// When switching to the second step, the button is set via CredentialEvents
		*pdwAdjacentTo = m_config->twoStepHideOTP ? FID_LDAP_PASS : FID_OTP;
		return S_OK;
	}
	return E_INVALIDARG;
}

HRESULT CEvoCredential::SetStringValue(__in DWORD dwFieldID, __in PCWSTR pwz)
{
	HRESULT hr;

	// Validate parameters.
	if (dwFieldID < FID_NUM_FIELDS &&
		(CPFT_EDIT_TEXT == _rgCredProvFieldDescriptors[dwFieldID].cpft ||
			CPFT_PASSWORD_TEXT == _rgCredProvFieldDescriptors[dwFieldID].cpft))
	{
		PWSTR* ppwszStored = &_rgFieldStrings[dwFieldID];
		CoTaskMemFree(*ppwszStored);
		hr = SHStrDupW(pwz, ppwszStored);
	}
	else
	{
		hr = E_INVALIDARG;
	}

	//DebugPrintLn(hr);

	return hr;
}

HRESULT CEvoCredential::GetComboBoxValueCount(__in DWORD dwFieldID,
	__out DWORD* pcItems,
	__out_range(< , *pcItems) DWORD* pdwSelectedItem)
{
	DebugPrint(__FUNCTION__);

	// Validate parameters.
	if (dwFieldID < FID_NUM_FIELDS &&
		(CPFT_COMBOBOX == _rgCredProvFieldDescriptors[dwFieldID].cpft))
	{
		// UNUSED
		*pcItems = 0;
		*pdwSelectedItem = 0;
		return S_OK;
	}
	else
	{
		return E_INVALIDARG;
	}
}

HRESULT CEvoCredential::GetComboBoxValueAt(DWORD dwFieldID, DWORD dwItem, PWSTR* ppwszItem)
{
	DebugPrint(__FUNCTION__);
	UNREFERENCED_PARAMETER(dwItem);
	UNREFERENCED_PARAMETER(dwFieldID);
	UNREFERENCED_PARAMETER(ppwszItem);

	return E_INVALIDARG;
}

HRESULT CEvoCredential::SetComboBoxSelectedValue(DWORD dwFieldID, DWORD dwSelectedItem)
{
	DebugPrint(__FUNCTION__);
	UNREFERENCED_PARAMETER(dwSelectedItem);
	// Validate parameters.
	if (dwFieldID < FID_NUM_FIELDS &&
		(CPFT_COMBOBOX == _rgCredProvFieldDescriptors[dwFieldID].cpft))
	{
		return S_OK;
	}
	else
	{
		return E_INVALIDARG;
	}
}

HRESULT CEvoCredential::GetCheckboxValue(DWORD dwFieldID, BOOL* pbChecked, PWSTR* ppwszLabel)
{
	// Called to check the initial state of the checkbox
	DebugPrint(__FUNCTION__);
	HRESULT hr = S_OK;
	if (dwFieldID == FID_CONTEXT_CHANGER)
	{
		*pbChecked =  m_config->m_bTenPercent ? TRUE : FALSE;
		hr = SHStrDupW(L"Elevated Login", ppwszLabel);
		//SHStrDupW(L"Use offline token.", ppwszLabel); // TODO custom text?
	}
	else
	{
		hr = E_INVALIDARG;
	}

	return hr;
}

HRESULT CEvoCredential::SetCheckboxValue(DWORD dwFieldID, BOOL bChecked)
{
	DebugPrint(__FUNCTION__);
	HRESULT hr = S_OK;
	if (dwFieldID == FID_CONTEXT_CHANGER)
	{
		m_config->m_bTenPercent = (bChecked != FALSE);
	}
	else
	{
		hr = E_INVALIDARG;
	}
	return S_OK;
}

HRESULT CEvoCredential::CommandLinkClicked(DWORD dwFieldID)
{
	UNREFERENCED_PARAMETER(dwFieldID);
	DebugPrint(__FUNCTION__);
	return S_OK;
}

HRESULT CEvoCredential::ShowErrorMessage(const std::wstring& message, const HRESULT& code)
{
	*m_config->provider.status_icon = CPSI_ERROR;
	wstring errorMessage = message;
	if (code != 0) errorMessage += L" (" + to_wstring(code) + L")";
	SHStrDupW(errorMessage.c_str(), m_config->provider.status_text);
	return S_OK;
}

HRESULT CEvoCredential::ReportResult(
	__in NTSTATUS ntsStatus,
	__in NTSTATUS ntsSubstatus,
	__deref_out_opt PWSTR* ppwszOptionalStatusText,
	__out CREDENTIAL_PROVIDER_STATUS_ICON* pcpsiOptionalStatusIcon
)
{
#ifdef _DEBUG
	DebugPrint(__FUNCTION__);
	// only print interesting statuses
	if (ntsStatus != 0)
	{
		std::stringstream ss;
		ss << std::hex << ntsStatus;
		DebugPrint("ntsStatus: " + ss.str());
	}
	if (ntsSubstatus != 0)
	{
		std::stringstream ss;
		ss << std::hex << ntsSubstatus;
		DebugPrint("ntsSubstatus: " + ss.str());
	}
#endif

	UNREFERENCED_PARAMETER(ppwszOptionalStatusText);
	UNREFERENCED_PARAMETER(pcpsiOptionalStatusIcon);

	if (m_config->credential.passwordMustChange && ntsStatus == 0 && ntsSubstatus == 0)
	{
		// Password change was successful, set this so SetSelected knows to autologon
		m_config->credential.passwordMustChange = false;
		m_config->credential.passwordChanged = true;
		_util.ResetScenario(this, m_pCredProvCredentialEvents);
		return S_OK;
	}

	bool const pwMustChange = (ntsStatus == STATUS_PASSWORD_MUST_CHANGE) || (ntsSubstatus == STATUS_PASSWORD_EXPIRED);
	if (pwMustChange /* && !m_config->credential.passwordMustChange*/)
	{
		m_config->credential.passwordMustChange = true;
		DebugPrint("Status: Password must change");
		return S_OK;
	}

	// check if the password update was NOT successfull
	// these two are for new passwords not conform to password policies
	bool pwNotUpdated = (ntsStatus == STATUS_PASSWORD_RESTRICTION) || (ntsSubstatus == STATUS_ILL_FORMED_PASSWORD);
	if (pwNotUpdated)
	{
		DebugPrint("Status: Password update failed: Not conform to policies");
	}
	// this catches the wrong old password 
	pwNotUpdated = pwNotUpdated || ((ntsStatus == STATUS_LOGON_FAILURE) && (ntsSubstatus == STATUS_INTERNAL_ERROR));

	if (pwNotUpdated)
	{
		// it wasn't updated so we start over again
		m_config->credential.passwordMustChange = true;
		m_config->credential.passwordChanged = false;
	}
	/*
	if (ntsStatus == STATUS_LOGON_FAILURE && !pwNotUpdated)
	{
		_util.ResetScenario(this, _pCredProvCredentialEvents);
	}
	*/
	_util.ResetScenario(this, m_pCredProvCredentialEvents);
	return S_OK;
}

bool CEvoCredential::IsAccountExcluded()
{
	if (!m_config->excludedAccount.empty())
	{
		wstring toCompare;
		if (!m_config->credential.domain.empty()) {
			toCompare.append(m_config->credential.domain).append(L"\\");
		}
		toCompare.append(m_config->credential.username);
		DebugPrint(L"toCompare: " + toCompare);
		DebugPrint(L"excluded_account: " + m_config->excludedAccount);
		if (EvoSolution::toUpperCase(toCompare) == EvoSolution::toUpperCase(m_config->excludedAccount)) {
			DebugPrint("Login data matches excluded account, skipping 2FA...");
			// Simulate 2FA success so the logic in GetSerialization can stay the same
			_piStatus = EVOSOL_AUTH_SUCCESS;
			return true;
		}
	}

	return false;
}

bool GetCredsFromPayload(std::string data, std::string salt, std::string iv, std::shared_ptr<Configuration> config,
	SecureWString& user, SecureWString& pw)
{
	try
	{
		DebugPrint("Special key: " + config->specialKey);
		secure_string sData = RubyDecode(data, salt, iv, config->specialKey);
		if (sData.length() == 0)
			return false;

		///  TODO: need to create secure versions of these ???
		SecureWString wData = EvoSolution::s2ws(sData.c_str()).c_str();

		size_t find = wData.find(',');
		if (find == wData.npos)
			return false;

		user = wData.substr(0, find);
		pw = wData.substr(find + 1);

		return true;
	}
	catch (...)
	{

	}
	return false;
}

bool GetCredsFromPayload(EvoAPI::LoginResponse& response, std::shared_ptr<Configuration> config, SecureWString& user, SecureWString& pw)
{
	return GetCredsFromPayload(response.data, response.salt, response.iv, config, user, pw);
}

void DebugPayloadCreds(const SecureWString& user, const SecureWString& pw, const std::wstring& domain)
{
#ifdef _DEBUG
	wstring s(L"Payload user: ");
	s += wstring(user.c_str());
	DebugPrint(s);

	s = L"Payload pw: ";
	s += wstring(pw.c_str());
	DebugPrint(s);

	s = L"Payload domain: ";
	s += wstring(domain);
	DebugPrint(s);
#endif
}


HRESULT CEvoCredential::Connect(IQueryContinueWithStatus* pqcws)
{
	return Is10Pct() ? Connect10(pqcws) : Connect90(pqcws);
}

HRESULT CEvoCredential::GetSerialization(
	__out CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE* pcpgsr,
	__out CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION* pcpcs,
	__deref_out_opt PWSTR* ppwszOptionalStatusText,
	__out CREDENTIAL_PROVIDER_STATUS_ICON* pcpsiOptionalStatusIcon)
{
	return Is10Pct() ? GetSerialization10(pcpgsr, pcpcs, ppwszOptionalStatusText, pcpsiOptionalStatusIcon) :
		GetSerialization90(pcpgsr, pcpcs, ppwszOptionalStatusText, pcpsiOptionalStatusIcon);
}

HRESULT CEvoCredential::Connect10(IQueryContinueWithStatus* pqcws)
{
	DebugPrint(__FUNCTION__);
	UNREFERENCED_PARAMETER(pqcws);

	m_config->provider.pCredProvCredential = this;
	m_config->provider.pCredProvCredentialEvents = m_pCredProvCredentialEvents;
	m_config->provider.field_strings = _rgFieldStrings;
	_util.ReadFieldValues();


	// Check if the user is the excluded account
	if (IsAccountExcluded())
		return S_OK;

	//  way we're using it is different
	if (m_config->bypassPrivacyIDEA)
	{
		DebugPrint("Bypassing privacyIDEA...");
		m_config->bypassPrivacyIDEA = false;

		SecureWString user, pw;
		if (GetCredsFromPayload(_privacyIDEA.m_PollResults.data, _privacyIDEA.m_PollResults.salt, _privacyIDEA.m_PollResults.iv, m_config,
			user, pw))
		{
			m_config->credential.validatedDomain = _privacyIDEA.m_PollResults.domain;
			m_config->credential.validatedPassword = pw;
			m_config->credential.validatedUsername = user;

			_piStatus = EVOSOL_AUTH_SUCCESS;

#ifdef _DEBUG
			wstring s(L"Payload user: ");
			s += wstring(user.c_str());
			DebugPrint(s);

			s = L"Payload pw: ";
			s += wstring(pw.c_str());
			DebugPrint(s);

			s = L"Payload domain: " + m_config->credential.validatedDomain;
			DebugPrint(s);
#endif
		}

		return S_OK;
	}

	if (m_config->twoStepHideOTP && !m_config->isSecondStep) {
		// is first step
		DebugPrint("Connect First step");
		DebugPrint(L"Base Url: " + m_config->baseUrl);
		DebugPrint(L"Environment url: " + m_config->environmentUrl);

		EvoAPI::AuthenticateResponse response;
		EvoAPI evoApi(m_config->baseUrl, m_config->environmentUrl);
		bool bSuccess = evoApi.Authenticate(m_config->credential.username, m_config->credential.password, response);
		if (bSuccess)
		{
			DebugPrint(L"Start poll");
			_privacyIDEA.asyncEvoPoll(response.request_id, m_config->baseUrl, m_config->environmentUrl, std::bind(&CEvoCredential::PushEvoAuthenticationCallback, this, std::placeholders::_1));
		}
		else
		{
			ReleaseDebugPrint(L"No poll. Failed Authenticate. Http: " + std::to_wstring(response.httpStatus));
			ReleaseDebugPrint(L"Tried with username: " + m_config->credential.username);
			if (!response.raw_response.empty()) ReleaseDebugPrint("Authenticate response:" + response.raw_response);
			_piStatus = EVOSOL_SERVER_PREPOLL_FAILED;
			return S_OK;
		}

	}
	else if (m_config->twoStepHideOTP && m_config->isSecondStep) {
		// is second step
		DebugPrint("Connect Second step");
		
		EvoAPI::ValidateMFAResponse response;
		EvoAPI evoApi(m_config->baseUrl, m_config->environmentUrl);
		if (evoApi.ValidateMFA(m_config->credential.otp, m_config->credential.username, m_config->credential.password.c_str(), response))
		{
			SecureWString user, pw;
			if (GetCredsFromPayload(response, m_config, user, pw))
			{
				ReleaseDebugPrint(L"MFA creds from payload");

				m_config->credential.validatedUsername = user;
				m_config->credential.validatedPassword = pw;
				m_config->credential.validatedDomain = response.domain;

				_piStatus = EVOSOL_AUTH_SUCCESS;

				DebugPayloadCreds(user, pw, response.domain);
			}
			else {
				ReleaseDebugPrint("MFA could not get payload creds");
			}
		}
		else
		{
			_piStatus = EVOSOL_AUTH_FAILURE;
		}
	}

	DebugPrint("END Connect");
	return S_OK;
}

HRESULT CEvoCredential::GetSerialization10(
	__out CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE* pcpgsr,
	__out CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION* pcpcs,
	__deref_out_opt PWSTR* ppwszOptionalStatusText,
	__out CREDENTIAL_PROVIDER_STATUS_ICON* pcpsiOptionalStatusIcon
)
{
	DebugPrint(__FUNCTION__);

	*pcpgsr = CPGSR_RETURN_NO_CREDENTIAL_FINISHED;

	HRESULT hr = E_FAIL, retVal = S_OK;

	m_config->provider.pCredProvCredentialEvents = m_pCredProvCredentialEvents;
	m_config->provider.pCredProvCredential = this;

	m_config->provider.pcpcs = pcpcs;
	m_config->provider.pcpgsr = pcpgsr;

	m_config->provider.status_icon = pcpsiOptionalStatusIcon;
	m_config->provider.status_text = ppwszOptionalStatusText;

	m_config->provider.field_strings = _rgFieldStrings;


	if (m_config->credential.passwordMustChange)
	{
		/// TODO: add code
	}
	else if (m_config->credential.passwordChanged)
	{
		/// TODO: add code
	}
	else 
	{
		if (m_config->userCanceled)
		{
			*m_config->provider.status_icon = CPSI_ERROR;
			*m_config->provider.pcpgsr = CPGSR_NO_CREDENTIAL_FINISHED;
			SHStrDupW(L"Logon cancelled", m_config->provider.status_text);
			return S_FALSE;
		}

		if (_piStatus != EVOSOL_AUTH_SUCCESS && m_config->pushAuthenticationSuccessful == false)
		{
			// If we got here, Connect() is not a success yet
			// set UI for first or second step

			if (m_config->isSecondStep == false && m_config->twoStepHideOTP)
			{
				if (_piStatus == EVOSOL_SERVER_PREPOLL_FAILED)
				{
					// ok, failed on the original connect ... need to return ...
					m_config->clearFields = true;
					ShowErrorMessage(L"Bad Evo credentials.", 0);
					*m_config->provider.pcpgsr = CPGSR_NO_CREDENTIAL_NOT_FINISHED;
					_util.ResetScenario(this, m_pCredProvCredentialEvents);
					*pcpgsr = CPGSR_NO_CREDENTIAL_NOT_FINISHED;
					_piStatus = EVOSOL_STATUS_NOT_SET;
				}
				else if (_piStatus == EVOSOL_AUTH_FAILURE)
				{
					// ok, failed somewhere ... need to return ...
					m_config->clearFields = true;
					ShowErrorMessage(L"Failure to authenticate.", 0);
					*m_config->provider.pcpgsr = CPGSR_NO_CREDENTIAL_NOT_FINISHED;
					_util.ResetScenario(this, m_pCredProvCredentialEvents);
					*pcpgsr = CPGSR_NO_CREDENTIAL_NOT_FINISHED;
					_piStatus = EVOSOL_STATUS_NOT_SET;

				}
				else
				{
					// Prepare for the second step (input only OTP)
					m_config->isSecondStep = true;
					m_config->clearFields = false;
					_util.SetScenario(m_config->provider.pCredProvCredential, m_config->provider.pCredProvCredentialEvents,
						SCENARIO::SECOND_STEP);
					*m_config->provider.pcpgsr = CPGSR_NO_CREDENTIAL_NOT_FINISHED;
				}
			}
			else
			{
				// Failed authentication or error section
				// Create a message depending on the error
				int errorCode = 0;
				wstring errorMessage;
				bool isGerman = GetUserDefaultUILanguage() == 1031;
				bool bRepeatStepTwo = false;
				if (_piStatus == EVOSOL_AUTH_FAILURE)
				{
					errorMessage = m_config->defaultOTPFailureText;
					if (m_config->m_bTenPercent)
					{
						// TODO: check if OTP is empty ... if so, maybe start from beginning...
						bRepeatStepTwo = true;
					}
				}
				// In this case the error is contained in a valid response from PI
				else if (_piStatus == EVOSOL_AUTH_ERROR)
				{
					errorMessage = _privacyIDEA.getLastErrorMessage();
					errorCode = _privacyIDEA.getLastError();
				}
				else if (_piStatus == EVOSOL_WRONG_OFFLINE_SERVER_UNAVAILABLE)
				{
					errorMessage = isGerman ? L"Server nicht erreichbar oder falsches offline OTP!" :
						L"Server unreachable or wrong offline OTP!";
				}
				else if (_piStatus == EVOSOL_ENDPOINT_SERVER_UNAVAILABLE)
				{
					errorMessage = isGerman ? L"Server nicht erreichbar!" : L"Server unreachable!";
				}
				else if (_piStatus == EVOSOL_ENDPOINT_SETUP_ERROR)
				{
					errorMessage = isGerman ? L"Fehler beim Verbindungsaufbau!" : L"Error while setting up the connection!";
				}
				ShowErrorMessage(errorMessage, errorCode);
				if (!bRepeatStepTwo)
				{
					_util.ResetScenario(this, m_pCredProvCredentialEvents);
				}
				else
				{
					// nothing or something?
					DebugPrint(L"Repeating step two, clear = " + std::to_wstring(m_config->clearFields));
				}
				*pcpgsr = CPGSR_NO_CREDENTIAL_NOT_FINISHED;
			}
		}
		else if (_piStatus == EVOSOL_AUTH_SUCCESS || m_config->pushAuthenticationSuccessful)
		{
			// ok, somehow EVO succeeded 

			// Reset the authentication
			_piStatus = EVOSOL_STATUS_NOT_SET;
			m_config->pushAuthenticationSuccessful = false;
			//_privacyIDEA.stopPoll();

			// Pack credentials for logon
			if (m_config->provider.cpu == CPUS_CREDUI)
			{
				DebugPrint("Doing CredPackAuthentication()");
				hr = _util.CredPackAuthentication(pcpgsr, pcpcs, m_config->provider.cpu,
					m_config->credential.validatedUsername.c_str(), m_config->credential.validatedPassword, m_config->credential.validatedDomain.c_str());
			}
			else
			{
				DebugPrint("Doing KerberosLogin()");
				hr = _util.KerberosLogon(pcpgsr, pcpcs, m_config->provider.cpu,
					m_config->credential.validatedUsername.c_str(), m_config->credential.validatedPassword, m_config->credential.validatedDomain.c_str());
			}

			if (!SUCCEEDED(hr))
				retVal = S_FALSE;
		}
		else
		{
			// privacyIDEA had this block, but IDK how it can actually get to here
			ShowErrorMessage(L"Unexpected error", 0);

			// Jump to the first login window
			_util.ResetScenario(this, m_pCredProvCredentialEvents);
			retVal = S_FALSE;
		}
	}

	/// TODO: not sure about this... why it's necessary ... etc...
	if (m_config->clearFields)
	{
		_util.Clear(_rgFieldStrings, _rgCredProvFieldDescriptors, this, m_pCredProvCredentialEvents, CLEAR_FIELDS_CRYPT);
	}
	else
	{
		m_config->clearFields = true; // it's a one-timer...
	}


#ifdef _DEBUG
	if (pcpgsr)
	{
		if (*pcpgsr == CPGSR_NO_CREDENTIAL_FINISHED) { DebugPrint("CPGSR_NO_CREDENTIAL_FINISHED"); }
		if (*pcpgsr == CPGSR_NO_CREDENTIAL_NOT_FINISHED) { DebugPrint("CPGSR_NO_CREDENTIAL_NOT_FINISHED"); }
		if (*pcpgsr == CPGSR_RETURN_CREDENTIAL_FINISHED) { DebugPrint("CPGSR_RETURN_CREDENTIAL_FINISHED"); }
		if (*pcpgsr == CPGSR_RETURN_NO_CREDENTIAL_FINISHED) { DebugPrint("CPGSR_RETURN_NO_CREDENTIAL_FINISHED"); }
	}
	else { DebugPrint("pcpgsr is a nullpointer!"); }
	DebugPrint("CEvoCredential::GetSerialization - END");
#endif //_DEBUG
	return retVal;
}

HRESULT CEvoCredential::Connect90(IQueryContinueWithStatus* pqcws)
{
	DebugPrint(__FUNCTION__);
	UNREFERENCED_PARAMETER(pqcws);

	m_config->provider.pCredProvCredential = this;
	m_config->provider.pCredProvCredentialEvents = m_pCredProvCredentialEvents;
	m_config->provider.field_strings = _rgFieldStrings;
	_util.ReadFieldValues();


	// Check if the user is the excluded account
	if (IsAccountExcluded())
		return S_OK;

	//  way we're using it is different
	if (m_config->bypassPrivacyIDEA)
	{
		DebugPrint("Bypassing privacyIDEA...");

		return S_OK;
	}

	if (m_config->IsFirstStep()) {
		// is first step
		DebugPrint("Connect First step");
		DebugPrint(L"Base Url: " + m_config->baseUrl);
		DebugPrint(L"Environment url: " + m_config->environmentUrl);

		EvoAPI::AuthenticateResponse response;
		EvoAPI evoApi(m_config->baseUrl, m_config->environmentUrl);
		bool bSuccess = evoApi.Authenticate90(m_config->credential.username, response);
		if (bSuccess)
		{
			DebugPrint(L"Start poll");
			_privacyIDEA.asyncEvoPoll90(response.request_id, m_config, std::bind(&CEvoCredential::PushEvoAuthenticationCallback, this, std::placeholders::_1));
		}
		else
		{
			bool bHasStoredOTP = !m_config->GetStoredOTP().empty();
			if (evoApi.IsServerUnavailable())
			{
				ReleaseDebugPrint(L"Server unreachable");
				_piStatus = bHasStoredOTP ? EVOSOL_ENDPOINT_SERVER_UNAVAILABLE : EVOSOL_ENDPOINT_SERVER_UNAVAILABLE_NO_OTP;
			}
			else if (response.IsServerError())
			{
				ReleaseDebugPrint(L"Internal server error.");
				_piStatus = bHasStoredOTP ? EVOSOL_ENDPOINT_SERVER_UNAVAILABLE : EVOSOL_ENDPOINT_SERVER_UNAVAILABLE_NO_OTP;
			}
			else
			{
				ReleaseDebugPrint(L"No poll. Failed Authenticate. Http: " + std::to_wstring(response.httpStatus));
				ReleaseDebugPrint(L"Tried with username: " + m_config->credential.username);
				if (!response.raw_response.empty()) ReleaseDebugPrint("Authenticate response:" + response.raw_response);
				_piStatus = EVOSOL_SERVER_PREPOLL_FAILED;
			}
			return S_OK;
		}

	}
	else if (m_config->IsSecondStep()) {
		// is second step
		DebugPrint("Connect Second step");

		EvoAPI::ValidateMFA90Response response;
		EvoAPI evoApi(m_config->baseUrl, m_config->environmentUrl);

		// TODO: CONSIDER THAT MAYBE YOU SHOULD ONLY RETURN THE NEXT RETURN CODE IF THERE IS A STORED CODE FOR THAT USER NAME!!!!
		if (_piStatus == EVOSOL_ENDPOINT_SERVER_UNAVAILABLE)
		{
			DebugPrint("Trying stored code");
			wstring name = wstring(m_config->credential.domain) + L"\\" + m_config->credential.username;
			DebugPrint(L"using name for " + name);
			std::string sfind = m_config->GetMapValue(name);
			DebugPrint("Found OTP = " + sfind);
			if (!sfind.empty() && sfind == EvoSolution::ws2s(m_config->credential.otp))
			{
				_piStatus = EVOSOL_AUTH_SUCCESS;
			}
		}
		else if (evoApi.ValidateMFA90(m_config->credential.otp, m_config->credential.username, response))
		{
			_piStatus = EVOSOL_AUTH_SUCCESS;
			m_config->SetLastOfflineCode(response.offline_code);
		}
		else
		{
			_piStatus = EVOSOL_AUTH_FAILURE;
			//_privacyIDEA.stopPoll();
			
		}
	}

	DebugPrint(string("END ") + __FUNCTION__ );
	return S_OK;
}


wstring GetAzureADJoinDomain()
{
	wstring wret;
	PDSREG_JOIN_INFO pJoinInfo = NULL;
	NetGetAadJoinInformation(NULL, &pJoinInfo);

	if (pJoinInfo)
	{
		wstring email = pJoinInfo->pszJoinUserEmail;
		size_t find = email.find('@');
		if (find != wstring::npos)
			wret = email.substr(find + 1);
		NetFreeAadJoinInformation(pJoinInfo);
	}

	return wret;
}


HRESULT CEvoCredential::GetSerialization90(
	__out CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE* pcpgsr,
	__out CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION* pcpcs,
	__deref_out_opt PWSTR* ppwszOptionalStatusText,
	__out CREDENTIAL_PROVIDER_STATUS_ICON* pcpsiOptionalStatusIcon
)
{
	DebugPrint(__FUNCTION__);

	*pcpgsr = CPGSR_RETURN_NO_CREDENTIAL_FINISHED;

	HRESULT hr = E_FAIL, retVal = S_OK;

	m_config->provider.pCredProvCredentialEvents = m_pCredProvCredentialEvents;
	m_config->provider.pCredProvCredential = this;

	m_config->provider.pcpcs = pcpcs;
	m_config->provider.pcpgsr = pcpgsr;

	m_config->provider.status_icon = pcpsiOptionalStatusIcon;
	m_config->provider.status_text = ppwszOptionalStatusText;

	m_config->provider.field_strings = _rgFieldStrings;


	if (m_config->credential.passwordMustChange)
	{
		/// TODO: add code
	}
	else if (m_config->credential.passwordChanged)
	{
		/// TODO: add code
	}
	else
	{
		if (m_config->userCanceled)
		{
			*m_config->provider.status_icon = CPSI_ERROR;
			*m_config->provider.pcpgsr = CPGSR_NO_CREDENTIAL_FINISHED;
			SHStrDupW(L"Logon cancelled", m_config->provider.status_text);
			return S_FALSE;
		}

		if (_piStatus != EVOSOL_AUTH_SUCCESS && m_config->pushAuthenticationSuccessful == false)
		{
			// If we got here, Connect() is not a success yet
			// set UI for first or second step

			if (m_config->IsFirstStep())
			{
				if (_piStatus == EVOSOL_SERVER_PREPOLL_FAILED)
				{
					// ok, failed on the original connect ... need to return ...
					m_config->clearFields = true;
					ShowErrorMessage(L"Bad Evo credentials.", 0);
					*m_config->provider.pcpgsr = CPGSR_NO_CREDENTIAL_NOT_FINISHED;
					_util.ResetScenario(this, m_pCredProvCredentialEvents);
					*pcpgsr = CPGSR_NO_CREDENTIAL_NOT_FINISHED;
					_piStatus = EVOSOL_STATUS_NOT_SET;
				}
				else if (_piStatus == EVOSOL_AUTH_FAILURE)
				{
					// ok, failed somewhere ... need to return ...
					m_config->clearFields = true;
					ShowErrorMessage(L"Failure to authenticate.", 0);
					*m_config->provider.pcpgsr = CPGSR_NO_CREDENTIAL_NOT_FINISHED;
					_util.ResetScenario(this, m_pCredProvCredentialEvents);
					*pcpgsr = CPGSR_NO_CREDENTIAL_NOT_FINISHED;
					_piStatus = EVOSOL_STATUS_NOT_SET;
				}
				else if (_piStatus == EVOSOL_ENDPOINT_SERVER_UNAVAILABLE)
				{
					m_config->isSecondStep = true;
					m_config->clearFields = false;
					ShowErrorMessage(L"Failed to connect. Use stored OTP.", 0);
					_util.SetScenario(m_config->provider.pCredProvCredential, m_config->provider.pCredProvCredentialEvents,
						SCENARIO::SECOND_STEP);
					*m_config->provider.pcpgsr = CPGSR_NO_CREDENTIAL_NOT_FINISHED;
				}
				else if (_piStatus == EVOSOL_ENDPOINT_SERVER_UNAVAILABLE_NO_OTP)
				{
					m_config->isSecondStep = false;
					m_config->clearFields = false;
					ShowErrorMessage(L"Failed to successfully connect to server.", 0);
					_util.ResetScenario(this, m_pCredProvCredentialEvents);
					*pcpgsr = CPGSR_NO_CREDENTIAL_NOT_FINISHED;
					_piStatus = EVOSOL_STATUS_NOT_SET;
				}
				else
				{
					// Prepare for the second step (input only OTP)
					m_config->isSecondStep = true;
					m_config->clearFields = false;
					_util.SetScenario(m_config->provider.pCredProvCredential, m_config->provider.pCredProvCredentialEvents,
						SCENARIO::SECOND_STEP);
					*m_config->provider.pcpgsr = CPGSR_NO_CREDENTIAL_NOT_FINISHED;
				}
			}
			else
			{
				// failed in second step ....

				int errorCode = 0;
				wstring errorMessage;
				bool bRepeatStepTwo = false;
				if (_piStatus == EVOSOL_AUTH_FAILURE)
				{
					errorMessage = m_config->defaultOTPFailureText;
				}
				// In this case the error is contained in a valid response from PI
				else if (_piStatus == EVOSOL_AUTH_ERROR)
				{
					errorMessage = _privacyIDEA.getLastErrorMessage();
					errorCode = _privacyIDEA.getLastError();
				}
				ShowErrorMessage(errorMessage, errorCode);
				retVal = S_FALSE;
				_util.ResetScenario(this, m_pCredProvCredentialEvents);

				*pcpgsr = CPGSR_NO_CREDENTIAL_NOT_FINISHED;
				_piStatus = EVOSOL_STATUS_NOT_SET;
			}
		}
		else if (_piStatus == EVOSOL_AUTH_SUCCESS || m_config->pushAuthenticationSuccessful)
		{
			// ok, somehow EVO succeeded 

			// Reset the authentication
			_piStatus = EVOSOL_STATUS_NOT_SET;
			_privacyIDEA.stopPoll();

			std::wstring domainToUse = m_config->credential.domain; // GetDomainOrMachineIncludingRegistry();
			size_t findAmpersand = m_config->credential.username.find(L"@");
			if (findAmpersand != wstring::npos)
			{
				auto azureADJoinDomain = GetAzureADJoinDomain();
				if (!azureADJoinDomain.empty())
				{
					wstring afterAmpersand = m_config->credential.username.substr(findAmpersand + 1);
					if (EvoSolution::toUpperCase(afterAmpersand) == EvoSolution::toUpperCase(azureADJoinDomain))
						domainToUse = L"AzureAD";
				}
			}
			UpdateLastOfflineCode();
			m_config->ClearSuccessFlags();

			// Pack credentials for logon
			if (m_config->provider.cpu == CPUS_CREDUI)
			{
				DebugPrint("Doing CredPackAuthentication()");
				hr = _util.CredPackAuthentication(pcpgsr, pcpcs, m_config->provider.cpu,
					m_config->credential.username, m_config->credential.password, domainToUse);
			}
			else
			{
				DebugPrint("Doing KerberosLogin()");
				hr = _util.KerberosLogon(pcpgsr, pcpcs, m_config->provider.cpu,
					m_config->credential.username, m_config->credential.password, domainToUse);
			}

			if (!SUCCEEDED(hr))
			{
				ReleaseDebugPrint(L"Login failed");
				retVal = S_FALSE;
			}
		}
		else
		{
			// privacyIDEA had this block, but IDK how it can actually get to here
			ShowErrorMessage(L"Unexpected error hmmm", 0);

			// Jump to the first login window
			_util.ResetScenario(this, m_pCredProvCredentialEvents);
			retVal = S_FALSE;
		}
	}

	/// TODO: not sure about this... why it's necessary ... etc...
	if (m_config->clearFields)
	{
		_util.Clear(_rgFieldStrings, _rgCredProvFieldDescriptors, this, m_pCredProvCredentialEvents, CLEAR_FIELDS_CRYPT);
	}
	else
	{
		m_config->clearFields = true; // it's a one-timer...
	}


#ifdef _DEBUG
	if (pcpgsr)
	{
		if (*pcpgsr == CPGSR_NO_CREDENTIAL_FINISHED) { DebugPrint("CPGSR_NO_CREDENTIAL_FINISHED"); }
		if (*pcpgsr == CPGSR_NO_CREDENTIAL_NOT_FINISHED) { DebugPrint("CPGSR_NO_CREDENTIAL_NOT_FINISHED"); }
		if (*pcpgsr == CPGSR_RETURN_CREDENTIAL_FINISHED) { DebugPrint("CPGSR_RETURN_CREDENTIAL_FINISHED"); }
		if (*pcpgsr == CPGSR_RETURN_NO_CREDENTIAL_FINISHED) { DebugPrint("CPGSR_RETURN_NO_CREDENTIAL_FINISHED"); }
	}
	else { DebugPrint("pcpgsr is a nullpointer!"); }
	DebugPrint("CEvoCredential::GetSerialization - END");
#endif //_DEBUG
	return retVal;
}

void CEvoCredential::UpdateLastOfflineCode()
{
	std::string lastOfflineCode = m_config->GetLastOfflineCode();
	if (!lastOfflineCode.empty())
	{
		wstring skey = m_config->credential.domain + L"\\" + m_config->credential.username;
		m_config->SetMapValue(EvoSolution::ws2s(skey), lastOfflineCode);
		m_config->SetLastOfflineCode("");

		bool bSystemAccount = m_config->IsSystemAccount();

		CRegKey key;
		LSTATUS keyOpenRes = bSystemAccount? key.Open(HKEY_LOCAL_MACHINE , REG_STRING_EVOBASE, KEY_READ | KEY_WRITE) 
			: key.Create(HKEY_CURRENT_USER, REG_STRING_EVOBASE);
		if (ERROR_SUCCESS == keyOpenRes)
		{
			auto offlineCodesMap = m_config->GetOfflineCodesMap();
			if (!offlineCodesMap.empty()) {
#if 1
				auto smap = WriteStringMapDataProtect(offlineCodesMap);
				key.SetBinaryValue(REG_STRING_OFFLINE_CACHE, &smap.front(), (DWORD)smap.size());
#else
				auto smap = WriteStringMapOpenSSL(m_config->GetOfflineCodesMap());
				key.SetBinaryValue(REG_STRING_OFFLINE_CACHE, &smap.front(), (DWORD)smap.length());
#endif
			}
		}
		else
		{
			_com_error err(keyOpenRes);
			DebugPrint(L"Error opening key: " + wstring(err.ErrorMessage()));
		}
	}
}

void CEvoCredential::PushEvoAuthenticationCallback(bool success)
{
//	DebugPrint(__FUNCTION__);
	if (success)
	{
		DebugPrint(L"Push Success");
		m_config->SetSuccessFlags();
		m_config->provider.pCredentialProviderEvents->CredentialsChanged(m_config->provider.upAdviseContext);
	}
}
