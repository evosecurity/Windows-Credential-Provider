// CredentialFilter.cpp : Implementation of CCredentialFilter

#include "pch.h"
#include "CredentialFilter.h"
#include "../EvoCommon/Logger.h"
#include "../EvoCommon/Shared.h"

#import "EvoCredProvider.dll" exclude("_userHBITMAP", "__MIDL_IWinTypes_0007", "_userBITMAP", "wireHWND", "_RemotableHandle", "__MIDL_IWinTypes_0009")


HRESULT CCredentialFilter::Filter(CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus, DWORD dwFlags, GUID* rgclsidProviders,
	BOOL* rgbAllow, DWORD cProviders)
{
	UNREFERENCED_PARAMETER(dwFlags);
	DebugPrint(std::string(__FUNCTION__) + ": " + Shared::CPUStoString(cpus));

	switch (cpus)
	{
	case CPUS_LOGON:
	case CPUS_UNLOCK_WORKSTATION:
	case CPUS_CREDUI:
		break;
	case CPUS_CHANGE_PASSWORD:
		return E_NOTIMPL; // TODO 
	default:
		return E_INVALIDARG;
	}

	if (!Shared::IsRequiredForScenario(cpus, FILTER))
	{
		//DebugPrint("Filter is configured to be disabled for this scenario.");
		return S_OK;
	}

	for (DWORD i = 0; i < cProviders; i++)
	{
		if (IsEqualGUID(rgclsidProviders[i], __uuidof(EvoCredProviderLib::Provider)))
		{
			rgbAllow[i] = TRUE;
		}
		else
		{
			rgbAllow[i] = FALSE;
		}
	}

	return S_OK;
}

HRESULT CCredentialFilter::UpdateRemoteCredential(const CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION* pcpcsIn, CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION* pcpcsOut)
{
	//UNREFERENCED_PARAMETER(pcpsIn);
	//UNREFERENCED_PARAMETER(pcpcsOut);
	DebugPrint(__FUNCTION__);

	if (!pcpcsIn)
	{
		// no point continuing as there are no credentials
		return E_NOTIMPL;
	}

	// copy contents from pcpcsIn to pcpcsOut
	pcpcsOut->ulAuthenticationPackage = pcpcsIn->ulAuthenticationPackage;
	pcpcsOut->cbSerialization = pcpcsIn->cbSerialization;
	pcpcsOut->rgbSerialization = pcpcsIn->rgbSerialization;

	// set target CP to our CP
	pcpcsOut->clsidCredentialProvider = __uuidof(EvoCredProviderLib::Provider);

	// copy the buffer contents if needed
	if (pcpcsOut->cbSerialization > 0 && (pcpcsOut->rgbSerialization = (BYTE*)CoTaskMemAlloc(pcpcsIn->cbSerialization)) != NULL)
	{
		CopyMemory(pcpcsOut->rgbSerialization, pcpcsIn->rgbSerialization, pcpcsIn->cbSerialization);
		return S_OK;
	}
	else
	{
		return E_NOTIMPL;
	}
}