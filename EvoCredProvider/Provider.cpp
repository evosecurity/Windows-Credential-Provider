// Provider.cpp : Implementation of CProvider

#include "pch.h"
#include "Provider.h"
#include "EvoCredential.h"
#include "Logger.h"
#include <string>
#include "CoreLibs/Shared.h"
#include "Configuration.h"
#include "scenario.h"
#include "Utilities.h"
#include "helpers.h"
#include "guids.h"

using namespace std;

GUID CLSID_EvoCredentialProvider = __uuidof(Provider);

// CProvider

CProvider::CProvider()
	: m_pkiulSetSerialization(nullptr), m_dwSetSerializationCred(CREDENTIAL_PROVIDER_NO_DEFAULT)

{
	m_config = std::make_shared<Configuration>();
	Logger::Get().releaseLog = m_config->releaseLog;
}

CProvider::~CProvider()
{
}

void CProvider::_GetSerializedCredentials(PWSTR* username, PWSTR* password, PWSTR* domain)
{
	DebugPrint(__FUNCTION__);

	if (username)
	{
		if (_SerializationAvailable(SAF_USERNAME))
		{
			*username = (PWSTR)LocalAlloc(LMEM_ZEROINIT, m_pkiulSetSerialization->Logon.UserName.Length + sizeof(wchar_t));
			CopyMemory(*username, m_pkiulSetSerialization->Logon.UserName.Buffer, m_pkiulSetSerialization->Logon.UserName.Length);
		}
		else
		{
			*username = NULL;
		}
	}

	if (password)
	{
		if (_SerializationAvailable(SAF_PASSWORD))
		{
			*password = (PWSTR)LocalAlloc(LMEM_ZEROINIT, m_pkiulSetSerialization->Logon.Password.Length + sizeof(wchar_t));
			CopyMemory(*password, m_pkiulSetSerialization->Logon.Password.Buffer, m_pkiulSetSerialization->Logon.Password.Length);
		}
		else
		{
			*password = NULL;
		}
	}

	if (domain)
	{
		if (_SerializationAvailable(SAF_DOMAIN))
		{
			*domain = (PWSTR)LocalAlloc(LMEM_ZEROINIT, m_pkiulSetSerialization->Logon.LogonDomainName.Length + sizeof(wchar_t));
			CopyMemory(*domain, m_pkiulSetSerialization->Logon.LogonDomainName.Buffer, m_pkiulSetSerialization->Logon.LogonDomainName.Length);
		}
		else
		{
			*domain = NULL;
		}
	}
}

STDMETHODIMP CProvider::SetUsageScenario(_CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus, unsigned long dwFlags)
{
	m_cpus = cpus;
	m_dwCpusFlags = dwFlags;
#ifdef _DEBUG
	DebugPrint(string(__FUNCTION__) + ": " + Shared::CPUStoString(cpus));
	m_config->printConfiguration();
#endif
	HRESULT hr = E_INVALIDARG;

	m_config->provider.credPackFlags = dwFlags;
	m_config->provider.cpu = cpus;

	// Decide which scenarios to support here. Returning E_NOTIMPL simply tells the caller
	// that we're not designed for that scenario.

	switch (cpus)
	{
	case CPUS_LOGON:
	case CPUS_UNLOCK_WORKSTATION:
	case CPUS_CREDUI:
		hr = S_OK;
		break;
	case CPUS_CHANGE_PASSWORD:
	case CPUS_PLAP:
	case CPUS_INVALID:
		hr = E_NOTIMPL;
		break;
	default:
		return E_INVALIDARG;
	}

	if (hr == S_OK)
	{
		if (!Shared::IsRequiredForScenario(cpus, PROVIDER))
		{
			DebugPrint("CP is not enumerated because of the configuration for this scenario.");
			hr = E_NOTIMPL;
		}
	}

	DebugPrint("SetScenario result:");
	DebugPrint(hr);

	return hr;
}

STDMETHODIMP CProvider::SetSerialization(_CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION const*)
{
	return E_NOTIMPL;
}

STDMETHODIMP CProvider::Advise(ICredentialProviderEvents* pEvents, UINT_PTR upCookie)
{
	DebugPrint(__FUNCTION__);

	// should this member be CComPtr ??? probably!!!
	m_config->provider.pCredentialProviderEvents = pEvents;
	pEvents->AddRef();

	m_config->provider.upAdviseContext = upCookie;
	return S_OK;
}

STDMETHODIMP CProvider::UnAdvise(void)
{
	m_config->provider.pCredentialProviderEvents->Release();
	m_config->provider.upAdviseContext = NULL;
	return S_OK;
}

STDMETHODIMP CProvider::GetFieldDescriptorCount(unsigned long* pdwCount)
{
	DebugPrint(__FUNCTION__);

	*pdwCount = FID_NUM_FIELDS;

	return S_OK;
}

STDMETHODIMP CProvider::GetFieldDescriptorAt(unsigned long dwIndex, struct _CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR** ppcpfd)
{
	//DebugPrintLn(__FUNCTION__);
	HRESULT hr = E_FAIL;
	if (!m_config->provider.cpu)
	{
		return E_FAIL;
	}

	// Verify dwIndex is a valid field.
	if ((dwIndex < FID_NUM_FIELDS) && ppcpfd)
	{
		// Adjust the FieldDescriptor to copy depending on language and config
		wstring label = L"";
		switch (dwIndex)
		{
		case FID_USERNAME:
			label = Utilities::GetTranslatedText(TEXT_USERNAME);
			break;
		case FID_LDAP_PASS:
			label = Utilities::GetTranslatedText(TEXT_PASSWORD);
			break;
		case FID_NEW_PASS_1:
			label = Utilities::GetTranslatedText(TEXT_NEW_PASSWORD);
			break;
		case FID_NEW_PASS_2:
			label = Utilities::GetTranslatedText(TEXT_CONFIRM_PASSWORD);
			break;
		case FID_OTP:
			label = m_config->otpFieldText;
			if (label.empty())
				label = Utilities::GetTranslatedText(TEXT_OTP);
			break;
		default: break;
		}

		if (!label.empty())
		{
			s_rgScenarioCredProvFieldDescriptors[dwIndex].pszLabel = const_cast<LPWSTR>(label.c_str());
		}

		hr = FieldDescriptorCoAllocCopy(s_rgScenarioCredProvFieldDescriptors[dwIndex], ppcpfd);
	}
	else
	{
		hr = E_INVALIDARG;
	}

	return hr;
}

STDMETHODIMP CProvider::GetCredentialCount(
	__out DWORD* pdwCount,
	__out_range(< , *pdwCount) DWORD* pdwDefault,
	__out BOOL* pbAutoLogonWithDefault
)
{
	DebugPrint(__FUNCTION__);

	HRESULT hr = S_OK;

	*pdwCount = 1; //_dwNumCreds;
	*pdwDefault = 0; // this means we want to be the default
	*pbAutoLogonWithDefault = FALSE;
	if (m_config->noDefault)
	{
		*pdwDefault = CREDENTIAL_PROVIDER_NO_DEFAULT;
	}

	// if serialized creds are available, try using them to logon
	if (_SerializationAvailable(SAF_USERNAME) && _SerializationAvailable(SAF_PASSWORD))
	{
		*pdwDefault = 0;
		m_config->isRemoteSession = Shared::IsCurrentSessionRemote();
		if (m_config->isRemoteSession && !m_config->twoStepHideOTP)
		{
			*pbAutoLogonWithDefault = FALSE;
		}
		else
		{
			*pbAutoLogonWithDefault = TRUE;
		}
	}


	DebugPrint(hr);
	return hr;
}

STDMETHODIMP CProvider::GetCredentialAt(
	__in DWORD dwIndex,
	__deref_out ICredentialProviderCredential** ppcpc
)
{
	DebugPrint(__FUNCTION__);

	HRESULT hr = E_FAIL;
	const CREDENTIAL_PROVIDER_USAGE_SCENARIO usage_scenario = m_config->provider.cpu;


	if (!m_pCredential)
	{
		DebugPrint("Checking for serialized credentials");

		PWSTR serializedUser, serializedPass, serializedDomain;
		_GetSerializedCredentials(&serializedUser, &serializedPass, &serializedDomain);

		DebugPrint("Checking for missing credentials");

		if (usage_scenario == CPUS_UNLOCK_WORKSTATION && serializedUser == nullptr)
		{
			if (serializedUser == nullptr)
			{
				DebugPrint("Looking-up missing user name from session");

				DWORD dwLen = 0;

				if (!WTSQuerySessionInformation(WTS_CURRENT_SERVER_HANDLE,
					WTS_CURRENT_SESSION,
					WTSUserName,
					&serializedUser,
					&dwLen))
				{
					serializedUser = nullptr;
				}
			}

			if (serializedDomain == nullptr)
			{
				DebugPrint("Looking-up missing domain name from session");

				DWORD dwLen = 0;

				if (!WTSQuerySessionInformation(WTS_CURRENT_SERVER_HANDLE,
					WTS_CURRENT_SESSION,
					WTSDomainName,
					&serializedDomain,
					&dwLen))
				{
					serializedDomain = nullptr;
				}
			}
		}
		else if (usage_scenario == CPUS_LOGON || usage_scenario == CPUS_CREDUI)
		{
			if (serializedDomain == nullptr)
			{
				DebugPrint("Looking-up missing domain name from computer");

				NETSETUP_JOIN_STATUS join_status;

				if (!NetGetJoinInformation(
					nullptr,
					&serializedDomain,
					&join_status) == NERR_Success || join_status == NetSetupUnjoined || join_status == NetSetupUnknownStatus)
				{
					serializedDomain = nullptr;
				}
				DebugPrint("Found domain:");
				DebugPrint(serializedDomain);
			}
		}

		DebugPrint("Initializing CCredential");

		CEvoCredential* pCredential = NULL;
		CEvoCredential::CreateCredential(m_config, &m_pCredential);

		//m_pCredential = std::make_unique<CCredential>(m_config);

		hr = m_pCredential->Initialize(
			s_rgScenarioCredProvFieldDescriptors,
			Utilities::GetFieldStatePairFor(usage_scenario, m_config->twoStepHideOTP),
			serializedUser, serializedDomain, serializedPass);
	}
	else
	{
		hr = S_OK;
	}

	DebugPrint("Checking for successful initialization");

	if (FAILED(hr))
	{
		DebugPrint("Initialization failed");
		return hr;
	}

	DebugPrint("Checking for successful instantiation");

	if (!m_pCredential)
	{
		DebugPrint("Instantiation failed");
		return E_OUTOFMEMORY;
	}

	DebugPrint("Returning interface to credential");

	if ((dwIndex == 0) && ppcpc)
	{
		if (usage_scenario == CPUS_CREDUI)
		{
			DebugPrint("CredUI: returning an IID_ICredentialProviderCredential");
			hr = m_pCredential->QueryInterface(IID_ICredentialProviderCredential, reinterpret_cast<void**>(ppcpc));
		}
		else
		{
			DebugPrint("Non-CredUI: returning an IID_IConnectableCredentialProviderCredential");
			hr = m_pCredential->QueryInterface(IID_IConnectableCredentialProviderCredential, reinterpret_cast<void**>(ppcpc));
			//hr = _pccCredential->QueryInterface(IID_ICredentialProviderCredential, reinterpret_cast<void **>(ppcpc));
		}
	}
	else
	{
		hr = E_INVALIDARG;
	}

	DebugPrint(hr);

	return hr;
}

bool CProvider::_SerializationAvailable(SERIALIZATION_AVAILABLE_FOR checkFor)
{
	DebugPrint(__FUNCTION__);

	bool result = false;

	if (!m_pkiulSetSerialization)
	{
		DebugPrint("No serialized creds set");
	}
	else
	{
		switch (checkFor)
		{
		case SAF_USERNAME:
			result = m_pkiulSetSerialization->Logon.UserName.Length && m_pkiulSetSerialization->Logon.UserName.Buffer;
			break;
		case SAF_PASSWORD:
			result = m_pkiulSetSerialization->Logon.Password.Length && m_pkiulSetSerialization->Logon.Password.Buffer;
			break;
		case SAF_DOMAIN:
			result = m_pkiulSetSerialization->Logon.LogonDomainName.Length && m_pkiulSetSerialization->Logon.LogonDomainName.Buffer;
			break;
		}
	}

	return result;
}
