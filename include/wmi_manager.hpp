#pragma once
#include "abstract_singleton.hpp"

namespace SystemHealthCheck
{
	using TWmiCallback = std::function<void(std::map<std::string, std::string>)>;

	class CWMIManager : public CSingleton <CWMIManager>
	{
	public:
		CWMIManager();
		virtual ~CWMIManager();

		bool Initialize();
		void Release();

		bool CheckWMIStatus(bool bShouldRepair);
		bool CheckHasSecurityTools();

	protected:
		bool __IsServiceValid(bool bShouldRepair);
		bool __IsRestrictionsValid(bool bShouldRepair);
		bool __RepairService();

		bool __ExecuteQuery(const std::wstring& wstQuery, TWmiCallback cb);

	private:
		IWbemLocator* m_pWbemLocator;
		IWbemServices* m_pWbemServices;
	};
}
