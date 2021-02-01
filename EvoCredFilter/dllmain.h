// dllmain.h : Declaration of module class.

class CEvoCredFilterModule : public ATL::CAtlDllModuleT< CEvoCredFilterModule >
{
public :
	DECLARE_LIBID(LIBID_EvoCredFilterLib)
	DECLARE_REGISTRY_APPID_RESOURCEID(IDR_EVOCREDFILTER, "{010c13d3-a357-4db9-b3d4-6e83b87c31f8}")
};

extern class CEvoCredFilterModule _AtlModule;
