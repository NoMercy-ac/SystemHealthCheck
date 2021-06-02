#include "../include/pch.hpp"
#include "../include/wmi_manager.hpp"
#include "../include/log_manager.hpp"
#include "../include/com_error.hpp"
#include "../include/utilities.hpp"
#include "../include/redirected_io_pipe.hpp"

namespace SystemHealthCheck
{
	inline bool DumpWMIClassObject(int iAnalyseType, IWbemClassObject* pClassObject, int iIndentationLevel, TWmiCallback cb)
	{
		auto mDataMap = std::map<std::string, std::string>();

		SAFEARRAY* pStrNames;
		auto hError = pClassObject->GetNames(NULL, WBEM_FLAG_ALWAYS | WBEM_FLAG_NONSYSTEM_ONLY, NULL, &pStrNames);
		if (FAILED(hError))
			return false;

		auto lLowerBound = 0L;
		hError = SafeArrayGetLBound(pStrNames, 1, &lLowerBound);
		if (FAILED(hError))
			return false;

		auto lUpperBound = 0L;
		hError = SafeArrayGetUBound(pStrNames, 1, &lUpperBound);
		if (FAILED(hError))
			return false;

		auto lElementCount = lUpperBound - lLowerBound + 1;
		if (!lElementCount)
			return false;

		for (auto i = 0L; i < lElementCount; i++)
		{
			auto bszName = ((BSTR*)pStrNames->pvData)[i];

			VARIANT varVal = { 0 };
			CIMTYPE cymType = 0;
			hError = pClassObject->Get(bszName, 0, &varVal, &cymType, NULL);
			if (SUCCEEDED(hError))
			{
				if (wcscmp(bszName, L"TargetInstance") == 0)
				{
					DumpWMIClassObject(iAnalyseType, reinterpret_cast<IWbemClassObject*>(varVal.uintVal), iIndentationLevel + 1, cb);
				}

				else if (cymType == CIM_STRING)
				{
					if (varVal.bstrVal)
					{
						std::wstring wszName(bszName, SysStringLen(bszName));
						std::string szName(wszName.begin(), wszName.end());

						std::wstring wszValue(varVal.bstrVal, SysStringLen(varVal.bstrVal));
						std::string szValue(wszValue.begin(), wszValue.end());

						mDataMap[szName] = szValue;
					}
				}

				else
				{
					std::wstring wszName(bszName, SysStringLen(bszName));
					std::string szName(wszName.begin(), wszName.end());

					mDataMap[szName] = std::to_string(varVal.uintVal);
				}
			}
		}

		if (cb)
			cb(mDataMap);
		return true;
	}


	CWMIManager::CWMIManager() :
		m_pWbemLocator(nullptr), m_pWbemServices(nullptr)
	{
	}
	CWMIManager::~CWMIManager()
	{
	}

	void CWMIManager::Release()
	{
		SAFE_RELEASE(m_pWbemLocator);
		SAFE_RELEASE(m_pWbemServices);

		CoUninitialize();
	}

	bool CWMIManager::Initialize()
	{
		auto hr = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
		if (FAILED(hr))
		{
			CLogManager::Instance().Log(LL_ERR, fmt::format("CoInitialize failed with error: {0} {1}", fmt::ptr(reinterpret_cast<void*>(hr)), ComErrorMessage(hr)));
			return false;
		}

		hr = CoInitializeSecurity(NULL, -1, NULL, NULL, RPC_C_AUTHN_LEVEL_DEFAULT, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_NONE, NULL);
		if (FAILED(hr) && RPC_E_TOO_LATE != hr)
		{
			CLogManager::Instance().Log(LL_ERR, fmt::format("CoInitializeSecurity failed with error: {0} {1}", fmt::ptr(reinterpret_cast<void*>(hr)), ComErrorMessage(hr)));
			return false;
		}

		hr = CoCreateInstance(CLSID_WbemLocator, 0, CLSCTX_INPROC_SERVER, IID_IWbemLocator, (LPVOID*)&m_pWbemLocator);
		if (FAILED(hr))
		{
			CLogManager::Instance().Log(LL_ERR, fmt::format("CoCreateInstance failed with error: {0} {1}", fmt::ptr(reinterpret_cast<void*>(hr)), ComErrorMessage(hr)));
			return false;
		}

		hr = m_pWbemLocator->ConnectServer(L"ROOT\\SecurityCenter2", NULL, NULL, NULL, 0, NULL, NULL, &m_pWbemServices);
		if (FAILED(hr))
		{
			CLogManager::Instance().Log(LL_ERR, fmt::format("m_pWbemLocator->ConnectServer failed with error: {0} {1}", fmt::ptr(reinterpret_cast<void*>(hr)), ComErrorMessage(hr)));
			return false;
		}

		hr = CoSetProxyBlanket(m_pWbemServices, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, NULL, RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_NONE);
		if (FAILED(hr))
		{
			CLogManager::Instance().Log(LL_ERR, fmt::format("CoSetProxyBlanket failed with error: {0} {1}", fmt::ptr(reinterpret_cast<void*>(hr)), ComErrorMessage(hr)));
			return false;
		}

		return true;
	}

	bool CWMIManager::__IsServiceValid(bool bShouldRepair)
	{
		if (!CUtilites::Instance().IsServiceIntegirtyCorrupted("winmgmt"))
		{
			CLogManager::Instance().Log(LL_ERR, "WMI service integrity check failed!");
			if (bShouldRepair)
				this->__RepairService();
			return false;
		}

		if (!CUtilites::Instance().GetProcessIdFromProcessName("wmiprvse.exe"))
		{
			CLogManager::Instance().Log(LL_ERR, "WMI process not found!");
			if (bShouldRepair)
				this->__RepairService();
			return false;
		}

		return true;
	}
	bool CWMIManager::__IsRestrictionsValid(bool bShouldRepair)
	{
		auto nBufSize = 1024UL;
		auto dwBuffer = 0UL;

		auto dwFlags = KEY_READ | KEY_QUERY_VALUE;
		if (CUtilites::Instance().IsSysWow64())
			dwFlags |= KEY_WOW64_64KEY;

		HKEY hKey = nullptr;
		auto res = RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Control\\WMI\\Restrictions", 0, dwFlags, &hKey);
		if (res == ERROR_FILE_NOT_FOUND)
		{
			return true;
		}
		else if (res != ERROR_SUCCESS)
		{
			CLogManager::Instance().Log(LL_ERR, fmt::format("RegOpenKeyExA failed with status: {0}", res));
			return false;
		}

		CLogManager::Instance().Log(LL_ERR, "WMI restrictions key detected!");

		if (bShouldRepair)
		{
			res = RegDeleteKeyA(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Control\\WMI\\Restrictions");
			if (res != ERROR_SUCCESS)
			{
				CLogManager::Instance().Log(LL_ERR, fmt::format("RegDeleteKeyA failed with status: {0}", res));
				RegCloseKey(hKey);
				return false;
			}
		}

		RegCloseKey(hKey);
		return false;
	}
	bool CWMIManager::__RepairService()
	{
		auto bRet = false;

		char szSysPath[MAX_PATH] = { '\0' };
		if (!GetSystemDirectoryA(szSysPath, MAX_PATH))
		{
			CLogManager::Instance().Log(LL_ERR, fmt::format("GetSystemDirectoryA failed with error: {0}", GetLastError()));
			return false;
		}
		
		// Set working directory for CMD
		auto stCmd = fmt::format("cd {0}", szSysPath);
		bRet = CRedirectedIOPipe::Instance().RunCommand(stCmd);
		if (!bRet)
		{
			CLogManager::Instance().Log(LL_ERR, "Set system working directory cmd is failed!");
			return false;
		}

		// Auto repair by system
		if (CUtilites::Instance().GetWindowsMajorVersion() == 10)
		{
			stCmd = "winmgmt /verifyrepository";
			bRet = CRedirectedIOPipe::Instance().RunCommand(stCmd);
			if (bRet)
			{
				stCmd = "winmgmt /salvagerepository";
				bRet = CRedirectedIOPipe::Instance().RunCommand(stCmd);
				if (bRet)
				{
					stCmd = "winmgmt /resetrepository";
					bRet = CRedirectedIOPipe::Instance().RunCommand(stCmd);
				}
			}
		}
		else if (IsWindows7OrGreater())
		{
			stCmd = "winmgmt /salvagerepository";
			bRet = CRedirectedIOPipe::Instance().RunCommand(stCmd);
		}
		else if (IsWindowsXPOrGreater())
		{
			stCmd = "winmgmt /clearadap";
			bRet = CRedirectedIOPipe::Instance().RunCommand(stCmd);
			if (bRet)
			{
				stCmd = "winmgmt /kill";
				bRet = CRedirectedIOPipe::Instance().RunCommand(stCmd);
				if (bRet)
				{
					stCmd = "winmgmt /unregserver";
					bRet = CRedirectedIOPipe::Instance().RunCommand(stCmd);
					if (bRet)
					{
						stCmd = "winmgmt /regserver";
						bRet = CRedirectedIOPipe::Instance().RunCommand(stCmd);
						if (bRet)
						{
							stCmd = "winmgmt /resyncperf";
							bRet = CRedirectedIOPipe::Instance().RunCommand(stCmd);
						}
					}
				}
			}
		}

		CLogManager::Instance().Log(LL_SYS, fmt::format("WMI repair with cmd is completed. Result: {0}", bRet));
		
		// Manual repair
		if (!bRet)
		{
			do
			{
				if (!CUtilites::Instance().ChangeServiceStartType("winmgmt", SERVICE_DISABLED))
				{
					CLogManager::Instance().Log(LL_ERR, "WMI service start type change failed!");
					break;
				}

				if (!CUtilites::Instance().ServiceStop("winmgmt"))
				{
					CLogManager::Instance().Log(LL_ERR, "WMI service stop failed!");
					break;
				}

				std::error_code ec;
				if (std::filesystem::exists(fmt::format("{0}\\wbem\\repository", szSysPath), ec) || ec)
				{
					const auto stBackupFolder = fmt::format("{0}\\wbem\\repository_backup_shc_{1}", szSysPath, CUtilites::Instance().GetCurrentTimestamp());
					if (std::filesystem::exists(stBackupFolder, ec) && !ec)
					{
						CLogManager::Instance().Log(LL_ERR, fmt::format("WMI repo backup folder: {0} already exist!"));
						break;
					}		

					std::filesystem::rename(fmt::format("{0}\\wbem\\repository", szSysPath), stBackupFolder, ec);
					if (ec)
					{
						CLogManager::Instance().Log(LL_ERR, fmt::format("WMI repo folder rename failed with error: {0}", ec.message()));
						break;
					}
				}

				stCmd = fmt::format("cd {0}\\wbem", szSysPath);
				bRet = CRedirectedIOPipe::Instance().RunCommand(stCmd);
				if (!bRet)
				{
					CLogManager::Instance().Log(LL_ERR, "Set wbem working directory cmd is failed!");
					break;
				}

				stCmd = fmt::format("for /f %s in ('dir /b *.mof') do mofcomp %s", szSysPath);
				if (!CRedirectedIOPipe::Instance().RunCommand(stCmd))
				{
					CLogManager::Instance().Log(LL_ERR, "Run WMI repair command (1) failed!");
					break;
				}

				stCmd = fmt::format("for /f %s in ('dir /b en-us\\*.mfl') do mofcomp en-us\\%s", szSysPath);
				if (!CRedirectedIOPipe::Instance().RunCommand(stCmd))
				{
					CLogManager::Instance().Log(LL_ERR, "Run WMI repair command (2) failed!");
					break;
				}

				stCmd = "wmiprvse /regserver";
				if (!CRedirectedIOPipe::Instance().RunCommand(stCmd))
				{
					CLogManager::Instance().Log(LL_ERR, "Run WMI repair command (3) failed!");
					break;
				}

				if (!CUtilites::Instance().ChangeServiceStartType("winmgmt", SERVICE_AUTO_START))
				{
					CLogManager::Instance().Log(LL_ERR, "WMI service start type restore failed!");
					break;
				}

				if (!CUtilites::Instance().ServiceStart("winmgmt"))
				{
					CLogManager::Instance().Log(LL_ERR, "WMI service start failed!");
					break;
				}

				bRet = true;
			} while (FALSE);

			CLogManager::Instance().Log(LL_SYS, fmt::format("WMI repair as manual is completed. Result: {0}", bRet));
		}

		return bRet;
	}

	bool CWMIManager::CheckWMIStatus(bool bShouldRepair)
	{
		return __IsServiceValid(bShouldRepair) && __IsRestrictionsValid(bShouldRepair);
	}

	bool CWMIManager::CheckHasSecurityTools()
	{
		auto bRet = true;

		auto fnQueryExecuter = [&](std::map<std::string, std::string> data) {
			if (data.empty())
			{
				CLogManager::Instance().Log(LL_ERR, "Query have not returned any data!");
				bRet = false;
			}
			return;
		};

		const auto lstQueries = {
			L"SELECT * FROM AntiVirusProduct",
			L"SELECT * FROM AntiSpywareProduct"
		};

		auto nFailCount = 0;

		auto idx = 0;
		for (const auto& wstQuery : lstQueries)
		{
			idx++;

#ifdef _DEBUG
			CLogManager::Instance().Log(LL_SYS, fmt::format(L"Executing query: '{0}' ...", wstQuery));
#endif

			if (!this->__ExecuteQuery(wstQuery, fnQueryExecuter))
			{
				CLogManager::Instance().Log(LL_ERR, fmt::format(L"Query: {0} execute failed!", wstQuery));
				nFailCount++;
			}

			if (!bRet)
				break;
		}

		if (nFailCount == 2)
		{
			CLogManager::Instance().Log(LL_ERR, "Any security tool does not exist in system!");
			bRet = false;
		}

		return bRet;
	}

	bool CWMIManager::__ExecuteQuery(const std::wstring& wstQuery, TWmiCallback cb)
	{
		if (!m_pWbemServices || wstQuery.empty() || !cb)
		{
			CLogManager::Instance().Log(LL_ERR, "ExecuteQuery Sanity check failed!");
			return false;
		}

		IEnumWbemClassObject* pEnumerator = nullptr;
		auto hr = m_pWbemServices->ExecQuery(L"WQL", (BSTR)wstQuery.c_str(), WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY, nullptr, &pEnumerator);
		if (FAILED(hr) || !pEnumerator)
		{
			CLogManager::Instance().Log(LL_ERR, fmt::format("m_pWbemServices->ExecQuery failed with error: {0} {1}", fmt::ptr(reinterpret_cast<void*>(hr)), ComErrorMessage(hr)));
			return false;
		}

		auto bEnumerated = false;
		while (pEnumerator)
		{
			ULONG uReturn = 0;
			IWbemClassObject* pclsObj = nullptr;
			hr = pEnumerator->Next(WBEM_INFINITE, 1, &pclsObj, &uReturn);
			if (FAILED(hr) || 0 == uReturn)
				break;

			if (!DumpWMIClassObject(0, pclsObj, 0, cb))
				break;

			bEnumerated = true;
			if (pclsObj)
				pclsObj->Release();
		}

		if (pEnumerator)
			pEnumerator->Release();
		return bEnumerated;
	}
}
