// TestCredProvider.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#ifndef STRICT
#define STRICT
#endif

#include <SDKDDKVer.h>

#define _ATL_APARTMENT_THREADED
#define _ATL_NO_AUTOMATIC_NAMESPACE
#define _ATL_CSTRING_EXPLICIT_CONSTRUCTORS	// some CString constructors will be explicit
#define ATL_NO_ASSERT_ON_DESTROY_NONEXISTENT_WINDOW

#include <atlbase.h>
#include <atlcom.h>
#include <atlctl.h>

#include <iostream>
#include <codecvt>
#include <credentialprovider.h>

using namespace std;
using namespace ATL;

class CTestCredProviderModule : public ATL::CAtlModule
{
public:
    void InitStuff()
    {
        //m_hInst = m_hInstResource = GetModuleHandle(NULL);
        _pAtlModule = this;
    }

    HRESULT AddCommonRGSReplacements(IRegistrarBase*)
    {
        return E_NOTIMPL;
    }

} m_AtlModule;

class ATL_NO_VTABLE CEventSupplier
    : public CComObjectRootEx<CComSingleThreadModel>
    , public ICredentialProviderEvents
{
public:
    CEventSupplier()
    {

    }

    ~CEventSupplier()
    {

    }

    DECLARE_NOT_AGGREGATABLE(CEventSupplier)

    BEGIN_COM_MAP(CEventSupplier)
        COM_INTERFACE_ENTRY(ICredentialProviderEvents)
    END_COM_MAP()

    DECLARE_PROTECT_FINAL_CONSTRUCT()

    HRESULT FinalConstruct()
    {
        return S_OK;
    }

    void FinalRelease()
    {
    }

    HRESULT CredentialsChanged(UINT_PTR upAdviseContext)
    {
        return S_OK;
    }

    static HRESULT Create(ICredentialProviderEvents** ppEvts)
    {
        CComObject<CEventSupplier>* pObj = NULL;
        HRESULT hr;
        if (FAILED(hr = CComObject<CEventSupplier>::CreateInstance(&pObj)))
            return hr;

        pObj->AddRef();
        *ppEvts = pObj;
        return S_OK;
    }


};

class ATL_NO_VTABLE CCredentialEventsSupplier
    : public CComObjectRootEx<CComSingleThreadModel>
    , public ICredentialProviderCredentialEvents
{
public:
    DECLARE_NOT_AGGREGATABLE(CCredentialEventsSupplier)

    BEGIN_COM_MAP(CCredentialEventsSupplier)
        COM_INTERFACE_ENTRY(ICredentialProviderCredentialEvents)
    END_COM_MAP()

    DECLARE_PROTECT_FINAL_CONSTRUCT()

    HRESULT FinalConstruct()
    {
        return S_OK;
    }

    void FinalRelease()
    {
    }

    static HRESULT Create(CCredentialEventsSupplier**  ppEvts)
    {
        *ppEvts = NULL;
        CComObject<CCredentialEventsSupplier>* pObject = NULL;
        HRESULT hr = CComObject<CCredentialEventsSupplier>::CreateInstance(&pObject);
        if (FAILED(hr))
            return hr;
        pObject->AddRef();
        *ppEvts = pObject;

        return S_OK;
    }

    // dummy funcs

    HRESULT SetFieldState(ICredentialProviderCredential*, DWORD, CREDENTIAL_PROVIDER_FIELD_STATE) { return S_OK; }
    HRESULT SetFieldInteractiveState(ICredentialProviderCredential*, DWORD, CREDENTIAL_PROVIDER_FIELD_INTERACTIVE_STATE) { return S_OK; }
    HRESULT SetFieldString(ICredentialProviderCredential*, DWORD, LPCWSTR) { return S_OK; }
    HRESULT SetFieldCheckbox(ICredentialProviderCredential*, DWORD, BOOL, LPCWSTR) { return S_OK; }
    HRESULT SetFieldBitmap(ICredentialProviderCredential*, DWORD, HBITMAP) { return S_OK; }
    HRESULT SetFieldComboBoxSelectedItem(ICredentialProviderCredential*, DWORD, DWORD) { return S_OK; }
    HRESULT DeleteFieldComboBoxItem(ICredentialProviderCredential*, DWORD, DWORD) { return S_OK; }
    HRESULT AppendFieldComboBoxItem(ICredentialProviderCredential*, DWORD, LPCWSTR) { return S_OK; }
    HRESULT SetFieldSubmitButton(ICredentialProviderCredential*, DWORD, DWORD) { return S_OK; }
    HRESULT OnCreatingWindow(HWND*) { return S_OK; }

};

class CComInit
{
public:
    CComInit()
    {
        _hr = CoInitialize(NULL);
    }
    ~CComInit()
    {
        if (S_OK == _hr)
        {
            CoUninitialize();
        }
    }

    HRESULT _hr = E_FAIL;
};

template <class T>
class CCoTaskMemory
{
public:
    T** operator&()
    {
        return &m_pv;
    }
    T* operator->()
    {
        return m_pv;
    }
    void Free()
    {
        if (m_pv)
        {
            T* pv = m_pv;
            m_pv = NULL;
            CoTaskMemFree(pv);
        }
    }
protected:

    T* m_pv = NULL;
};

class CCredentialProviderFieldDescriptor : public CCoTaskMemory< CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR>
{
public:
    ~CCredentialProviderFieldDescriptor()
    {
        if (m_pv)
        {
            CoTaskMemFree(m_pv->pszLabel);
        }
    }
};


std::string ws2s(const std::wstring& ws)
{
    using convert_typeX = std::codecvt_utf8<wchar_t>;
    std::wstring_convert<convert_typeX, wchar_t> converterX;

    return converterX.to_bytes(ws);

}


int main()
{
    m_AtlModule.InitStuff();
    cout << "starting with TestCredProvider.exe" << endl;

    CComInit _init;
    LPCWSTR pwz = L"{a81f782d-cf30-439a-bad8-645d9862ea99}";
    //pwz = L"{7970503B-F356-4B59-9413-E57C2F530F7B}";
    CLSID clsid = CLSID_NULL;
    CLSIDFromString(pwz, &clsid);


    CComPtr<IUnknown> lpUnk;
    //HRESULT hr = lpUnk.CoCreateInstance(L"EvoCredProvider.Provider");
    HRESULT hr = lpUnk.CoCreateInstance(clsid);

    if (!lpUnk)
    {
        cout << "failed to create object" << endl;
        return - 1;
    }

    CComQIPtr<ICredentialProvider> lpCredProvider(lpUnk);

    if (!lpCredProvider)
    {
        cout << "failed QI for ICredentialProvider " << endl;
        return -1;
    }

    HINSTANCE hMod = GetModuleHandle(_T("evocredprovider90.dll"));
    if (hMod)
    {
        auto f = GetProcAddress(hMod, "TestReadWriteMap");
        if (f != nullptr)
            f();

        f = GetProcAddress(hMod, "TestReadWriteCryptMap");
        if (f != nullptr)
            f();

        f = GetProcAddress(hMod, "TestReadWriteCryptMapDataProtected");
        if (f != nullptr)
            f();
    }



    lpCredProvider->SetUsageScenario(CPUS_LOGON, 0);


    CComPtr<ICredentialProviderEvents> pEvents;
    if (FAILED(CEventSupplier::Create(&pEvents)))
    {
        cout << "failed to create event supplier" << endl;
        return -1;
    }
    
    lpCredProvider->Advise(pEvents, 12345678);

    DWORD dw1, dw2;
    BOOL b1;
    hr = lpCredProvider->GetCredentialCount(&dw1, &dw2, &b1);


    DWORD dwFieldDescriptorCount = 0;
    lpCredProvider->GetFieldDescriptorCount(&dwFieldDescriptorCount);
    for (DWORD dw = 0; dw < dwFieldDescriptorCount; ++dw)
    {
        CCredentialProviderFieldDescriptor pcpfs;
        if (SUCCEEDED(lpCredProvider->GetFieldDescriptorAt(dw, &pcpfs)))
        {
            cout << "Index (" << dw << "): " << ws2s(pcpfs->pszLabel) << endl;
        }
    }

    CComPtr<ICredentialProviderCredential> lpCred;
    lpCredProvider->GetCredentialAt(0, &lpCred);

    CComPtr< CCredentialEventsSupplier> pCredentialEventsSupplier;
    CCredentialEventsSupplier::Create(&pCredentialEventsSupplier);
    lpCred->Advise(pCredentialEventsSupplier);

    BOOL bAutoLogon;
    lpCred->SetSelected(&bAutoLogon);

    cout << "Auto logon: " << bAutoLogon << endl;


    lpCred->SetDeselected();

    lpCred->SetSelected(&bAutoLogon);
    lpCred->SetStringValue(3, L"willc");
    lpCred->SetStringValue(4, L"jordan");
    lpCred->SetStringValue(5, L"123456");

    lpCred->CommandLinkClicked(23);
    lpCred->SetCheckboxValue(34, TRUE);

    CCoTaskMemory<WCHAR> pString;
    lpCred->GetComboBoxValueAt(1, 0, &pString);

    CComPtr< IConnectableCredentialProviderCredential> pConnectableCredential;
    lpCred->QueryInterface(&pConnectableCredential);

    pConnectableCredential->Connect(NULL); // this is where privacyIDEA validates the second factor of the 2FA

    lpCred->UnAdvise();
    lpCredProvider->UnAdvise();

    cout << "finished with TestCredProvider.exe" << endl;
}

