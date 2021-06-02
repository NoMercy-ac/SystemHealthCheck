#pragma once
#include "abstract_singleton.hpp"

namespace SystemHealthCheck
{
	class CWinUpdateManager : public CSingleton <CWinUpdateManager>
	{
	public:
		CWinUpdateManager();
		virtual ~CWinUpdateManager();

		bool Initialize();
		void Release();

		bool HasAnyUpdate();

	protected:
		static VARIANT_BOOL __BoolToVariantBool(bool bBool)
		{
			return bBool ? VARIANT_TRUE : VARIANT_FALSE;
		}
		static bool __VariantBoolToBool(VARIANT_BOOL vbBool)
		{
			return (vbBool == VARIANT_TRUE);
		}

	private:
		IUpdateSession2* m_pUpdateSession2;
		ISystemInformation* m_pSystemInfo;
		IUpdateSearcher* m_pUpdateSearcher;
		IUpdateCollection* m_pUpdateList;
	};
}
