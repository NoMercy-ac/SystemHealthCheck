#pragma once
#include "abstract_singleton.hpp"

namespace SystemHealthCheck
{
	class CNetworkManager : public CSingleton <CNetworkManager>
	{
	public:
		CNetworkManager();
		virtual ~CNetworkManager();

		bool Initialize();
		void Release();

		bool CheckInternetStatus();
		bool CheckNoMercyServerStatus();
		bool CheckNoMercyVersion(uint32_t nCurrentVersion);
	};
}
