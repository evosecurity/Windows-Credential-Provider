// CredentialFilter.h : Declaration of the CCredentialFilter

#pragma once
#include "resource.h"       // main symbols



#include "EvoCredFilter_i.h"



#if defined(_WIN32_WCE) && !defined(_CE_DCOM) && !defined(_CE_ALLOW_SINGLE_THREADED_OBJECTS_IN_MTA)
#error "Single-threaded COM objects are not properly supported on Windows CE platform, such as the Windows Mobile platforms that do not include full DCOM support. Define _CE_ALLOW_SINGLE_THREADED_OBJECTS_IN_MTA to force ATL to support creating single-thread COM object's and allow use of it's single-threaded COM object implementations. The threading model in your rgs file was set to 'Free' as that is the only threading model supported in non DCOM Windows CE platforms."
#endif

using namespace ATL;


// CCredentialFilter

class ATL_NO_VTABLE CCredentialFilter :
	public CComObjectRootEx<CComSingleThreadModel>,
	public CComCoClass<CCredentialFilter, &CLSID_CredentialFilter>,
	public ICredentialProviderFilter
{
public:
	CCredentialFilter()
	{
	}

DECLARE_REGISTRY_RESOURCEID(106)

DECLARE_NOT_AGGREGATABLE(CCredentialFilter)

BEGIN_COM_MAP(CCredentialFilter)
	COM_INTERFACE_ENTRY(ICredentialProviderFilter)
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

	STDMETHOD(Filter)(CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus, DWORD, GUID*, BOOL*, DWORD);
	STDMETHOD(UpdateRemoteCredential)(const CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION*, CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION*);


};

OBJECT_ENTRY_AUTO(__uuidof(CredentialFilter), CCredentialFilter)
