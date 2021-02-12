// Provider.h : Declaration of the CProvider

#pragma once
#include "resource.h"       // main symbols

#include "EvoCredProvider_i.h"

class Configuration;
class CEvoCredential;

#if defined(_WIN32_WCE) && !defined(_CE_DCOM) && !defined(_CE_ALLOW_SINGLE_THREADED_OBJECTS_IN_MTA)
#error "Single-threaded COM objects are not properly supported on Windows CE platform, such as the Windows Mobile platforms that do not include full DCOM support. Define _CE_ALLOW_SINGLE_THREADED_OBJECTS_IN_MTA to force ATL to support creating single-thread COM object's and allow use of it's single-threaded COM object implementations. The threading model in your rgs file was set to 'Free' as that is the only threading model supported in non DCOM Windows CE platforms."
#endif

using namespace ATL;

enum SERIALIZATION_AVAILABLE_FOR
{
	SAF_USERNAME,
	SAF_PASSWORD,
	SAF_DOMAIN
};

// CProvider

class ATL_NO_VTABLE CProvider :
	public CComObjectRootEx<CComSingleThreadModel>,
	public CComCoClass<CProvider, &CLSID_Provider>,
	public ICredentialProvider
{
public:
	CProvider();
	~CProvider();

DECLARE_REGISTRY_RESOURCEID(106)

DECLARE_NOT_AGGREGATABLE(CProvider)

BEGIN_COM_MAP(CProvider)
	COM_INTERFACE_ENTRY(ICredentialProvider)
END_COM_MAP()

	DECLARE_PROTECT_FINAL_CONSTRUCT()

	HRESULT FinalConstruct()
	{
		return S_OK;
	}

	void FinalRelease()
	{
	}

public:


	STDMETHOD(SetUsageScenario)(CREDENTIAL_PROVIDER_USAGE_SCENARIO, DWORD);
	STDMETHOD(SetSerialization)(const CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION*);
	STDMETHOD(Advise)(ICredentialProviderEvents*, UINT_PTR);
	STDMETHOD(UnAdvise)();
	STDMETHOD(GetFieldDescriptorCount)(DWORD*);
	STDMETHOD(GetFieldDescriptorAt)(DWORD, CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR**);
	STDMETHOD(GetCredentialCount)(DWORD*, DWORD*, BOOL*);
	STDMETHOD(GetCredentialAt)(DWORD, ICredentialProviderCredential**);

	bool _SerializationAvailable(SERIALIZATION_AVAILABLE_FOR checkFor);
	void _GetSerializedCredentials(PWSTR* username, PWSTR* password, PWSTR* domain);

protected:
	_CREDENTIAL_PROVIDER_USAGE_SCENARIO m_cpus = CPUS_INVALID;
	DWORD m_dwCpusFlags = 0;

	CComPtr<ICredentialProviderEvents> m_pCredentialProviderEvents;
	UINT_PTR m_upCookie = 0;

	std::shared_ptr<Configuration> m_config;

	KERB_INTERACTIVE_UNLOCK_LOGON* m_pkiulSetSerialization;
	DWORD m_dwSetSerializationCred;

	CComPtr<CEvoCredential> m_pCredential;// = nullptr;
};

OBJECT_ENTRY_AUTO(__uuidof(Provider), CProvider)
