// dllmain.h : Declaration of module class.

class CTestCredProviderModule : public ATL::CAtlDllModuleT< CTestCredProviderModule >
{
public :
	DECLARE_LIBID(LIBID_TestCredProviderLib)
	DECLARE_REGISTRY_APPID_RESOURCEID(IDR_TESTCREDPROVIDER, "{a8d9a214-5fdd-48f5-ae11-30b1b7bdf8bd}")
};

extern class CTestCredProviderModule _AtlModule;
