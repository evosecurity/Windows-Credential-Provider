#pragma once

#include "Configuration.h"
#include "scenario.h"
#include "Utilities.h"
#include "EvoSolution.h"

#define NOT_EMPTY(NAME) \
	(NAME != NULL && NAME[0] != NULL)

#define ZERO(NAME) \
	SecureZeroMemory(NAME, sizeof(NAME))

using namespace ATL;

class ATL_NO_VTABLE CEvoCredential :
	public CComObjectRootEx<CComSingleThreadModel>,
	public IConnectableCredentialProviderCredential
{
public:
	CEvoCredential();

	~CEvoCredential();

	DECLARE_NOT_AGGREGATABLE(CEvoCredential)

	BEGIN_COM_MAP(CEvoCredential)
		COM_INTERFACE_ENTRY(IConnectableCredentialProviderCredential)
		COM_INTERFACE_ENTRY(ICredentialProviderCredential)
	END_COM_MAP()

	DECLARE_PROTECT_FINAL_CONSTRUCT()

	HRESULT FinalConstruct()
	{
		return S_OK;
	}

	static HRESULT CreateCredential(std::shared_ptr<Configuration> pConfiguration, CEvoCredential** ppCred);
	HRESULT Initialize(__in const CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR* rgcpfd,
		__in const FIELD_STATE_PAIR* rgfsp,
		__in_opt PWSTR user_name,
		__in_opt PWSTR domain_name,
		__in_opt PWSTR password
	);

	void SetConfiguration(std::shared_ptr<Configuration> pConfiguration)
	{
		m_config = pConfiguration;
		_util.SetConfiguration(pConfiguration);
	}

	HRESULT Advise(ICredentialProviderCredentialEvents* pcpe);
	HRESULT UnAdvise();
	HRESULT SetSelected(BOOL* pbAutoLogon);
	HRESULT SetDeselected();
	HRESULT GetFieldState(__in DWORD dwFieldID,
		__out CREDENTIAL_PROVIDER_FIELD_STATE* pcpfs,
		__out CREDENTIAL_PROVIDER_FIELD_INTERACTIVE_STATE* pcpfis);
	HRESULT GetStringValue(DWORD dwFieldID, PWSTR* ppwsz);
	HRESULT GetBitmapValue(DWORD dwFieldID, HBITMAP* phbmp);
	HRESULT GetSubmitButtonValue(DWORD dwFieldID, DWORD* pdwAdjacentTo);
	HRESULT SetStringValue(__in DWORD dwFieldID, __in PCWSTR pwz);
	HRESULT GetComboBoxValueCount(__in DWORD dwFieldID,
		__out DWORD* pcItems,
		__out_range(< , *pcItems) DWORD* pdwSelectedItem);
	HRESULT GetComboBoxValueAt(DWORD dwFieldID, DWORD dwItem, PWSTR* ppwszItem);
	HRESULT SetComboBoxSelectedValue(DWORD dwFieldID, DWORD dwSelectedItem);
	HRESULT GetCheckboxValue(DWORD dwFieldID, BOOL* pbChecked, PWSTR* ppwszLabel);
	HRESULT SetCheckboxValue(DWORD dwFieldID, BOOL bChecked);
	HRESULT CommandLinkClicked(DWORD dwFieldID);
	HRESULT ShowErrorMessage(const std::wstring& message, const HRESULT& code);
	HRESULT Disconnect() { return E_NOTIMPL; }
	HRESULT ReportResult(NTSTATUS ntsStatus, NTSTATUS ntsSubstatus, PWSTR* ppwszOptionalStatusText, CREDENTIAL_PROVIDER_STATUS_ICON* pcpsiOptionalStatusIcon);
	HRESULT Connect(IQueryContinueWithStatus* pqcws);
	HRESULT GetSerialization(CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE*, CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION*, LPWSTR*, CREDENTIAL_PROVIDER_STATUS_ICON*);

	HRESULT ConnectOrig(IQueryContinueWithStatus* pqcws);
	HRESULT GetSerializationOrig(CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE*, CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION*, LPWSTR*, CREDENTIAL_PROVIDER_STATUS_ICON*);

	void PushAuthenticationCallback(bool success);
protected:

	bool IsAccountExcluded();


	std::shared_ptr<Configuration> m_config;

	CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR	_rgCredProvFieldDescriptors[FID_NUM_FIELDS];	// An array holding the type and 
																							// name of each field in the tile.

	FIELD_STATE_PAIR						_rgFieldStatePairs[FID_NUM_FIELDS];          // An array holding the state of 
																						 // each field in the tile.

	wchar_t* _rgFieldStrings[FID_NUM_FIELDS];			 // An array holding the string 
																						 // value of each field. This is 
																						 // different from the name of 
																						 // the field held in 
																						 // _rgCredProvFieldDescriptors.

	CComPtr<ICredentialProviderCredentialEvents> m_pCredProvCredentialEvents;
	DWORD _dwComboIndex = 0;
	Utilities _util = nullptr;
	HRESULT _piStatus = E_FAIL;

	EvoSolution _privacyIDEA;
};

