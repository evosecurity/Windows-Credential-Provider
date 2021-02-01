// dllmain.h : Declaration of module class.

class CEvoCredProviderModule : public ATL::CAtlDllModuleT< CEvoCredProviderModule >
{
public :
	DECLARE_LIBID(LIBID_EvoCredProviderLib)
	DECLARE_REGISTRY_APPID_RESOURCEID(IDR_TESTCREDPROVIDER, "{a8d9a214-5fdd-48f5-ae11-30b1b7bdf8bd}")
};

extern class CEvoCredProviderModule _AtlModule;
