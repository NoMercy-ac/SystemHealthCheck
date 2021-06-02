#include "../include/pch.hpp"
#include "../include/utilities.hpp"
#include "../include/log_manager.hpp"
#include "../include/thread_enumerator.hpp"
#include "../include/simple_timer.hpp"

namespace SystemHealthCheck
{
	CUtilites::CUtilites()
	{
	}
	CUtilites::~CUtilites()
	{
	}

	std::string CUtilites::ToAnsiString(const std::wstring& wstBuffer)
	{
#ifdef _WIN32
#pragma warning(push) 
#pragma warning(disable: 4242 4244)
#endif // _WIN32
		const auto stBuffer = std::string(wstBuffer.begin(), wstBuffer.end());
#ifdef _WIN32
#pragma warning(push) 
#endif // _WIN32
		return stBuffer;
	}
	std::string CUtilites::GetErrorDetailsA(int nErrorCode)
	{
		char szBuffer[1024]{ '\0' };
		if (strerror_s(szBuffer, sizeof(szBuffer), nErrorCode))
			return szBuffer;
		return {};
	}
	std::wstring CUtilites::GetErrorDetailsW(int nErrorCode)
	{
		wchar_t wszBuffer[1024]{ L'\0' };
		if (_wcserror_s(wszBuffer, 1024, nErrorCode))
			return wszBuffer;
		return {};
	}
	std::string GetSystemErrorReason(DWORD dwErrorCode)
	{
		LPSTR lpszReason = nullptr;
		if (FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, NULL, dwErrorCode, 0, (LPSTR)&lpszReason, 0, nullptr))
			return lpszReason;
		return {};
	}
	DWORD CUtilites::GetCurrentTimestamp()
	{
		time_t curTime = { 0 };
		std::time(&curTime);
		return (DWORD)curTime;
	}
	DWORD CUtilites::GetWindowsMajorVersion()
	{
		static const auto hNtdll = LoadLibraryA("ntdll.dll");
		if (!hNtdll)
			return 0;

		typedef NTSTATUS(NTAPI* TRtlGetVersion)(PRTL_OSVERSIONINFOEXW lpVersionInformation);
		static const auto RtlGetVersion = reinterpret_cast<TRtlGetVersion>(GetProcAddress(hNtdll, "RtlGetVersion"));
		if (!RtlGetVersion)
			return 0;

		DWORD dwResult = 0;

		RTL_OSVERSIONINFOEXW verInfo = { 0 };
		verInfo.dwOSVersionInfoSize = sizeof(verInfo);

		if (RtlGetVersion(&verInfo) == 0)
			dwResult = verInfo.dwMajorVersion;

		return dwResult;
	}

	bool CUtilites::IsSysWow64()
	{
#ifdef _WIN64
		return false;
#else
		return ((DWORD)__readfsdword(0xC0) != 0);
#endif
	}

	bool CUtilites::ManageFsRedirection(bool bDisable, PVOID pCookie, PVOID* ppCookie)
	{
		if (IsWindowsVistaOrGreater() && IsSysWow64())
		{
			if (bDisable)
			{
				PVOID OldValue = nullptr;
				if (!Wow64DisableWow64FsRedirection(&OldValue))
				{
					CLogManager::Instance().Log(LL_ERR, fmt::format("Wow64DisableWow64FsRedirection failed with error: {0}", GetLastError()));
					return false;
				}
				if (ppCookie && OldValue) *ppCookie = OldValue;
			}
			else
			{
				if (!Wow64RevertWow64FsRedirection(pCookie))
				{
					CLogManager::Instance().Log(LL_ERR, fmt::format("Wow64RevertWow64FsRedirection failed with error: {0}", GetLastError()));
					return false;
				}
			}
		}
		return true;
	}

	SFileReadCtx CUtilites::ReadFileContent(const std::wstring& wstFileName)
	{
		const auto hFile = CreateFileW(wstFileName.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
		if (!hFile || hFile == INVALID_HANDLE_VALUE)
		{
			CLogManager::Instance().Log(LL_ERR, fmt::format(L"CreateFileW ({0}) failed with error: {1}", wstFileName, GetLastError()));
			return {};
		}

		const auto dwFileSize = GetFileSize(hFile, NULL);
		if (!dwFileSize || dwFileSize == INVALID_FILE_SIZE)
		{
			CLogManager::Instance().Log(LL_ERR, fmt::format(L"GetFileSize ({0}) failed with error: {1}", wstFileName, GetLastError()));
			CloseHandle(hFile);
			return {};
		}

		auto pFileBuffer = malloc(dwFileSize);
		if (!pFileBuffer)
		{
			CLogManager::Instance().Log(LL_ERR, fmt::format(L"Memory allocation for file ({0}) read buffer ({1}) failed with error: {2}", wstFileName, dwFileSize, GetErrorDetailsW(errno)));
			CloseHandle(hFile);
			return {};
		}
		memset(pFileBuffer, 0, dwFileSize);

		DWORD dwReadBytes = 0;
		auto bReadFile = ReadFile(hFile, pFileBuffer, dwFileSize, &dwReadBytes, nullptr);
		if (!bReadFile || dwReadBytes != dwFileSize)
		{
			CLogManager::Instance().Log(LL_ERR, fmt::format(L"ReadFile ({0}) failed with error: {1}", wstFileName, GetLastError()));
			CloseHandle(hFile);
			free(pFileBuffer);
			return {};
		}

		CloseHandle(hFile);
		return { pFileBuffer, dwReadBytes };
	}

	bool CUtilites::IsContentNumber(const std::string& s)
	{
		return !s.empty() && std::find_if(s.begin(), s.end(), [](unsigned char c) { return !std::isdigit(c); }) == s.end();
	}

	bool CUtilites::IsFileDigitalSigned(const std::wstring& wstFileName)
	{
		CLogManager::Instance().Log(LL_SYS, fmt::format(L"Digital sign check started! Target file: {0}", wstFileName));

		bool bResult = false;
		LONG lStatus = ERROR_SUCCESS;
		DWORD dwLastError = ERROR_SUCCESS;
		GUID WVTPolicyGUID = WINTRUST_ACTION_GENERIC_VERIFY_V2;

		// Initialize the WINTRUST_FILE_INFO structure.
		WINTRUST_FILE_INFO FileData = { 0 };
		FileData.cbStruct = sizeof(WINTRUST_FILE_INFO);
		FileData.pcwszFilePath = wstFileName.c_str();
		FileData.hFile = NULL;
		FileData.pgKnownSubject = NULL;

		// Initialize the WinVerifyTrust input data structure.
		WINTRUST_DATA WinTrustData = { 0 };
		WinTrustData.cbStruct = sizeof(WinTrustData);
		WinTrustData.pPolicyCallbackData = NULL; // Use default code signing EKU.	
		WinTrustData.pSIPClientData = NULL; // No data to pass to SIP.
		WinTrustData.dwUIChoice = WTD_UI_NONE; // Disable WVT UI.	
		WinTrustData.fdwRevocationChecks = WTD_REVOKE_NONE; // No revocation checking.	
		WinTrustData.dwUnionChoice = WTD_CHOICE_FILE; // Verify an embedded signature on a file.	
		WinTrustData.dwStateAction = WTD_STATEACTION_VERIFY; // Verify action.
		WinTrustData.hWVTStateData = NULL; // Verification sets this value.
		WinTrustData.pwszURLReference = NULL; // Not used.
		WinTrustData.dwUIContext = 0; // This is not applicable if there is no UI because it changes, the UI to accommodate running applications instead of installing applications.
		WinTrustData.pFile = &FileData; // Set pFile.

		// WinVerifyTrust verifies signatures as specified by the GUID and Wintrust_Data.
		lStatus = WinVerifyTrust(0, &WVTPolicyGUID, &WinTrustData);

		switch (lStatus)
		{
			case ERROR_SUCCESS:
			{
				bResult = true;
			} break;

			case TRUST_E_NOSIGNATURE:
			{
				// The file was not signed or had a signature 
				// that was not valid.

				// Get the reason for no signature.
				dwLastError = GetLastError();
				if (TRUST_E_NOSIGNATURE == dwLastError || TRUST_E_SUBJECT_FORM_UNKNOWN == dwLastError || TRUST_E_PROVIDER_UNKNOWN == dwLastError)
				{
					// The file was not signed.
					// CLogManager::Instance().Log(LL_WARN, fmt::format(L"The file \"{0}\" is not signed.", wstFileName));
				}
				else
				{
					// The signature was not valid or there was an error 
					// opening the file.
					CLogManager::Instance().Log(LL_ERR, fmt::format(L"An unknown error occurred trying to verify the signature of the \"{0}\" file.", wstFileName.c_str()));
				}
			} break;

			case TRUST_E_EXPLICIT_DISTRUST:
			{
				// The hash that represents the subject or the publisher 
				// is not allowed by the admin or user.
				CLogManager::Instance().Log(LL_ERR, "The signature is present, but specifically disallowed.");
			} break;

			case TRUST_E_SUBJECT_NOT_TRUSTED:
			{
				// The user clicked "No" when asked to install and run.
				CLogManager::Instance().Log(LL_ERR, "The signature is present, but not trusted.");
			} break;

			case CRYPT_E_SECURITY_SETTINGS:
			{
				/*
				The hash that represents the subject or the publisher
				was not explicitly trusted by the admin and the
				admin policy has disabled user trust. No signature,
				publisher or time stamp errors.
				*/
				CLogManager::Instance().Log(LL_ERR, "CRYPT_E_SECURITY_SETTINGS - The hash representing the subject or the publisher wasn't explicitly trusted by the admin and admin policy has disabled user trust. No signature, publisher or timestamp errors.");
			} break;

			default:
			{
				// The UI was disabled in dwUIChoice or the admin policy 
				// has disabled user trust. lStatus contains the 
				// publisher or time stamp chain error.
				CLogManager::Instance().Log(LL_ERR, fmt::format("WinVerifyTrust fail! Error code: {0}", lStatus));
			} break;
		}

		// Any hWVTStateData must be released by a call with close.
		WinTrustData.dwStateAction = WTD_STATEACTION_CLOSE;

		// Set created structs
		lStatus = WinVerifyTrust(0, &WVTPolicyGUID, &WinTrustData);

		SetLastError(lStatus);
		return bResult;
	}

	bool CUtilites::EnablePrivilege(const std::string& stPrivilege)
	{
		auto bRet = false;
		HANDLE hToken = nullptr;

		do
		{
			if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, &hToken))
			{
				CLogManager::Instance().Log(LL_ERR, fmt::format("OpenProcessToken fail! Error: {0}", GetLastError()));
				break;
			}

			LUID luid{};
			if (!LookupPrivilegeValueA(nullptr, stPrivilege.c_str(), &luid))
			{
				CLogManager::Instance().Log(LL_ERR, fmt::format("LookupPrivilegeValueA fail! Error: {0}", GetLastError()));
				break;
			}

			TOKEN_PRIVILEGES tp{};
			tp.PrivilegeCount = 1;
			tp.Privileges[0].Luid = luid;
			tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
			if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), nullptr, nullptr))
			{
				CLogManager::Instance().Log(LL_ERR, fmt::format("AdjustTokenPrivileges fail! Error: {0}", GetLastError()));
				break;
			}

			bRet = true;
		} while (FALSE);

		if (hToken)
			CloseHandle(hToken);

		return bRet;
	}

	bool CUtilites::ProcessIsItAlive(DWORD dwProcessId)
	{
		const auto hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
		if (!hSnap || hSnap == INVALID_HANDLE_VALUE)
		{
			CLogManager::Instance().Log(LL_ERR, fmt::format("CreateToolhelp32Snapshot fail! Error: {0}", GetLastError()));
			return false;
		}

		PROCESSENTRY32 pe = { 0 };
		pe.dwSize = sizeof(PROCESSENTRY32);

		if (Process32First(hSnap, &pe))
		{
			do {
				if (pe.th32ProcessID == dwProcessId)
				{
					CloseHandle(hSnap);
					return true;
				}
			} while (Process32Next(hSnap, &pe));
		}

		CloseHandle(hSnap);
		return false;
	}

	DWORD CUtilites::GetProcessIdFromProcessName(std::string stProcessName)
	{
		std::transform(stProcessName.begin(), stProcessName.end(), stProcessName.begin(), tolower);

		const auto hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
		if (!hSnap || hSnap == INVALID_HANDLE_VALUE)
		{
			CLogManager::Instance().Log(LL_ERR, fmt::format("CreateToolhelp32Snapshot fail! Error: {0}", GetLastError()));
			return 0;
		}

		PROCESSENTRY32 pe = { 0 };
		pe.dwSize = sizeof(PROCESSENTRY32);

		if (Process32First(hSnap, &pe))
		{
			do {
				std::string stCurrProcessName = pe.szExeFile;
				std::transform(stCurrProcessName.begin(), stCurrProcessName.end(), stCurrProcessName.begin(), tolower);

				if (stProcessName == stCurrProcessName)
				{
					CloseHandle(hSnap);
					return pe.th32ProcessID;
				}
			} while (Process32Next(hSnap, &pe));
		}

		CloseHandle(hSnap);
		return 0;
	}

	bool CUtilites::HasSuspendedThread(DWORD dwProcessId)
	{
		const auto threadEnumerator = std::make_unique<CThreadEnumerator>(dwProcessId);
		if (!threadEnumerator)
		{
			CLogManager::Instance().Log(LL_ERR, fmt::format("threadEnumerator allocation failed! Last error: {0}", GetLastError()));
			return false;
		}

		const auto systemThreadOwnerProcInfo = (WinAPI::SYSTEM_PROCESS_INFORMATION*)threadEnumerator->GetProcInfo();
		if (!systemThreadOwnerProcInfo)
		{
			CLogManager::Instance().Log(LL_ERR, fmt::format("systemThreadOwnerProcInfo is null! Last error: {0}", GetLastError()));
			return false;
		}

		const auto dwThreadCount = threadEnumerator->GetThreadCount(systemThreadOwnerProcInfo);
		if (!dwThreadCount)
		{
			CLogManager::Instance().Log(LL_ERR, fmt::format("dwThreadCount is null! Last error: {0}", GetLastError()));
			return false;
		}

		auto pk_Thread = (WinAPI::SYSTEM_THREAD_INFORMATION*)threadEnumerator->GetThreadList(systemThreadOwnerProcInfo);
		if (!pk_Thread)
		{
			CLogManager::Instance().Log(LL_ERR, fmt::format("pk_Thread is null! Last error: {0}", GetLastError()));
			return false;
		}

		for (std::size_t i = 0; i < dwThreadCount; i++)
		{
			const auto dwStartAddress = reinterpret_cast<DWORD_PTR>(pk_Thread->StartAddress);
			const auto dwThreadId = reinterpret_cast<DWORD_PTR>(pk_Thread->ClientId.UniqueThread);
			// APP_TRACE_LOG(LL_TRACE, "Thread: %u ID: %u State: %u Wait Reason: %u Start address: %p", i, dwThreadId, pk_Thread->ThreadState, pk_Thread->WaitReason, dwStartAddress);

			if (pk_Thread->ThreadState == WinAPI::Waiting && pk_Thread->WaitReason == WinAPI::Suspended)
			{
				CLogManager::Instance().Log(LL_ERR, fmt::format("Suspended thread found in process: {0} Thread ID: {1}", dwProcessId, dwThreadId));
				return true;
			}

			pk_Thread++;
		}

		return false;
	};

	bool CUtilites::IsServiceIntegirtyCorrupted(const std::string& stServiceName)
	{
		bool bRet = false;

		SC_HANDLE shServiceMgr = nullptr;
		SC_HANDLE shService = nullptr;
		LPBYTE lpBuffer = nullptr;

		do
		{
			shServiceMgr = OpenSCManagerA(NULL, NULL, SC_MANAGER_CONNECT | SC_MANAGER_QUERY_LOCK_STATUS);
			if (!shServiceMgr)
			{
				CLogManager::Instance().Log(LL_ERR, fmt::format("OpenSCManagerA fail! Error: {0}", GetLastError()));
				break;
			}

			shService = OpenServiceA(shServiceMgr, stServiceName.c_str(), SERVICE_QUERY_CONFIG | SERVICE_QUERY_STATUS);
			if (!shService)
			{
				CLogManager::Instance().Log(LL_ERR, fmt::format("OpenServiceA fail! Error: {0}", GetLastError()));
				break;
			}

			DWORD dwReqSize = 0;
			if (!QueryServiceStatusEx(shService, SC_STATUS_PROCESS_INFO, nullptr, 0, &dwReqSize) && !dwReqSize)
			{
				CLogManager::Instance().Log(LL_ERR, fmt::format("QueryServiceStatusEx(1) fail! Error: {0}", GetLastError()));
				break;
			}

			lpBuffer = (BYTE*)malloc(dwReqSize);
			if (!lpBuffer)
			{
				CLogManager::Instance().Log(LL_ERR, fmt::format("{0} bytes memory allocation failed with error: {1}", dwReqSize, errno));
				break;
			}

			if (!QueryServiceStatusEx(shService, SC_STATUS_PROCESS_INFO, lpBuffer, dwReqSize, &dwReqSize) || !lpBuffer)
			{
				CLogManager::Instance().Log(LL_ERR, fmt::format("QueryServiceStatusEx(2) fail! Error: {0}", GetLastError()));
				break;
			}

			const auto lpProcessStatus = (SERVICE_STATUS_PROCESS*)lpBuffer;
			if (!lpProcessStatus->dwProcessId)
			{
				CLogManager::Instance().Log(LL_ERR, "Service query buffer does not contain process id");
				break;
			}
			CLogManager::Instance().Log(LL_SYS, fmt::format("Service status: {0} Host process: {1}", lpProcessStatus->dwCurrentState, lpProcessStatus->dwProcessId));

			if (lpProcessStatus->dwCurrentState != SERVICE_RUNNING)
			{
				CLogManager::Instance().Log(LL_ERR, "Service is not running!");
				break;
			}

			if (!this->ProcessIsItAlive(lpProcessStatus->dwProcessId))
			{
				CLogManager::Instance().Log(LL_ERR, "Service host process not alive!");
				break;
			}

			if (this->HasSuspendedThread(lpProcessStatus->dwProcessId))
			{
				CLogManager::Instance().Log(LL_ERR, "Service host process contains suspended threads!");
				break;
			}

			bRet = true;
		} while (FALSE);

		if (shServiceMgr)
		{
			CloseServiceHandle(shServiceMgr);
			shServiceMgr = nullptr;
		}
		if (shService)
		{
			CloseServiceHandle(shService);
			shService = nullptr;
		}
		if (lpBuffer)
		{
			free(lpBuffer);
			lpBuffer = nullptr;
		}

		return bRet;
	}

	bool CUtilites::ChangeServiceStartType(const std::string& stServiceName, DWORD dwNewStartType)
	{
		auto bRet = false;

		SC_HANDLE shServiceMgr = nullptr;
		SC_HANDLE shService = nullptr;

		do
		{
			shServiceMgr = OpenSCManagerA(NULL, NULL, SC_MANAGER_CONNECT | SC_MANAGER_QUERY_LOCK_STATUS);
			if (!shServiceMgr)
			{
				CLogManager::Instance().Log(LL_ERR, fmt::format("OpenSCManagerA fail! Error: {0}", GetLastError()));
				break;
			}

			shService = OpenServiceA(shServiceMgr, stServiceName.c_str(), SERVICE_CHANGE_CONFIG | SERVICE_QUERY_STATUS);
			if (!shService)
			{
				CLogManager::Instance().Log(LL_ERR, fmt::format("OpenServiceA fail! Error: {0}", GetLastError()));
				break;
			}

			if (!ChangeServiceConfigA(shService, SERVICE_NO_CHANGE, dwNewStartType, SERVICE_NO_CHANGE, NULL, NULL, NULL, NULL, NULL, NULL, NULL))
			{
				CLogManager::Instance().Log(LL_ERR, fmt::format("ChangeServiceConfigA fail! Error: {0}", GetLastError()));
				break;
			}

			bRet = true;
		} while (FALSE);

		if (shService)
		{
			CloseServiceHandle(shService);
			shService = nullptr;
		}
		if (shServiceMgr)
		{
			CloseServiceHandle(shServiceMgr);
			shServiceMgr = nullptr;
		}

		return bRet;
	}

	bool CUtilites::ServiceStart(const std::string& stServiceName)
	{
		auto bRet = false;

		SC_HANDLE shServiceMgr = nullptr;
		SC_HANDLE shService = nullptr;
		SERVICE_STATUS sStatus{ 0 };

		do
		{
			shServiceMgr = OpenSCManagerA(NULL, NULL, SC_MANAGER_CONNECT | SC_MANAGER_QUERY_LOCK_STATUS);
			if (!shServiceMgr)
			{
				CLogManager::Instance().Log(LL_ERR, fmt::format("OpenSCManagerA fail! Error: {0}", GetLastError()));
				break;
			}

			shService = OpenServiceA(shServiceMgr, stServiceName.c_str(), SERVICE_START | SERVICE_QUERY_STATUS);
			if (!shService)
			{
				CLogManager::Instance().Log(LL_ERR, fmt::format("OpenServiceA fail! Error: {0}", GetLastError()));
				break;
			}

			if (QueryServiceStatus(shService, &sStatus) && (sStatus.dwCurrentState == SERVICE_START_PENDING || sStatus.dwCurrentState == SERVICE_RUNNING))
			{
				CLogManager::Instance().Log(LL_SYS, fmt::format("Service: {0} already started!", stServiceName.c_str()));
				bRet = true;
				break;
			}

			if (!StartServiceA(shService, 0, nullptr))
			{
				CLogManager::Instance().Log(LL_ERR, fmt::format("StartServiceA fail! Error: {0}", GetLastError()));
				break;
			}

			bRet = true;
		} while (FALSE);

		if (shService)
		{
			CloseServiceHandle(shService);
			shService = nullptr;
		}
		if (shServiceMgr)
		{
			CloseServiceHandle(shServiceMgr);
			shServiceMgr = nullptr;
		}

		return bRet;
	}

	bool CUtilites::ServiceStop(const std::string& stServiceName)
	{
		auto bRet = false;

		SC_HANDLE shServiceMgr = nullptr;
		SC_HANDLE shService = nullptr;
		SERVICE_STATUS sStatus{ 0 };

		do
		{
			shServiceMgr = OpenSCManagerA(NULL, NULL, SC_MANAGER_CONNECT | SC_MANAGER_QUERY_LOCK_STATUS);
			if (!shServiceMgr)
			{
				CLogManager::Instance().Log(LL_ERR, fmt::format("OpenSCManagerA fail! Error: {0}", GetLastError()));
				break;
			}

			shService = OpenServiceA(shServiceMgr, stServiceName.c_str(), SERVICE_STOP | SERVICE_QUERY_STATUS | DELETE);
			if (!shService)
			{
				CLogManager::Instance().Log(LL_ERR, fmt::format("OpenServiceA fail! Error: {0}", GetLastError()));
				break;
			}

			if (QueryServiceStatus(shService, &sStatus) && sStatus.dwCurrentState == SERVICE_STOPPED)
			{
				CLogManager::Instance().Log(LL_SYS, fmt::format("Service: {0} already stopped!", stServiceName.c_str()));
				bRet = true;
				break;
			}

			if (!ControlService(shService, SERVICE_CONTROL_STOP, &sStatus))
			{
				CLogManager::Instance().Log(LL_ERR, fmt::format("ControlService fail! Error: {0}", GetLastError()));
				break;
			}

			CLogManager::Instance().Log(LL_SYS, fmt::format("Stopping {0} ...", stServiceName.c_str()));
			Sleep(500);

			DWORD dwLastError = 0;
			auto pTimer = CSimpleTimer<std::chrono::milliseconds>();
			while (QueryServiceStatus(shService, &sStatus))
			{
				dwLastError = GetLastError();

				if (pTimer.diff() > 5000)
					break;

				if (sStatus.dwCurrentState != SERVICE_STOP_PENDING)
					break;

				CLogManager::Instance().Log(LL_SYS, fmt::format("Stopping pending {0} ...", stServiceName.c_str()));
				Sleep(500);
			}

			if (sStatus.dwCurrentState != SERVICE_STOPPED)
			{
				CLogManager::Instance().Log(LL_ERR, fmt::format("{0} Could Not Be Stopped. Status: {1} Last error: {2}", stServiceName.c_str(), sStatus.dwCurrentState, dwLastError));
				break;
			}

			CLogManager::Instance().Log(LL_SYS, fmt::format("{0} Has Successfully Stopped", stServiceName.c_str()));
			bRet = true;
		} while (FALSE);

		if (shService)
		{
			CloseServiceHandle(shService);
			shService = nullptr;
		}
		if (shServiceMgr)
		{
			CloseServiceHandle(shServiceMgr);
			shServiceMgr = nullptr;
		}

		return bRet;
	}

	bool CUtilites::IsKnownProcessor()
	{
		SYSTEM_INFO SysInfo = { 0 };
		GetNativeSystemInfo(&SysInfo);

		const auto type = SysInfo.dwProcessorType;
		const auto arch = SysInfo.wProcessorArchitecture;
		CLogManager::Instance().Log(LL_SYS, fmt::format("Processor type: {0} arch: {1}", type, arch));

		switch (type)
		{
			case PROCESSOR_INTEL_386:
			case PROCESSOR_INTEL_IA64:
			case PROCESSOR_AMD_X8664:
				break;
			default:
				return false;
		}

		switch (arch)
		{
			case PROCESSOR_ARCHITECTURE_INTEL:
			case PROCESSOR_ARCHITECTURE_IA64:
			case PROCESSOR_ARCHITECTURE_AMD64:
				return true;
		}

		return false;
	}
	bool CUtilites::IsSafeModeEnabled()
	{
		const auto nMetrics = GetSystemMetrics(SM_CLEANBOOT);
		return nMetrics > 0;
	}
	bool CUtilites::IsCompatibleModeEnabled(const std::string& stAppName)
	{
		const auto lstDirectorys = {
			HKEY_CURRENT_USER,
			HKEY_LOCAL_MACHINE
		};

		auto dwFlags = KEY_READ | KEY_QUERY_VALUE;
		if (IsSysWow64())
			dwFlags |= KEY_WOW64_64KEY;

		std::vector <std::string> vKeyList;
		for (const auto& hDirKey : lstDirectorys)
		{
			HKEY hKey{};
			auto res = RegOpenKeyExA(hDirKey, "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\AppCompatFlags\\Layers", 0, dwFlags, &hKey);
			if (res == ERROR_SUCCESS)
			{
				DWORD dwIndex = 0;
				while (true)
				{
					DWORD dwValueLen = MAX_PATH;
					char szValueName[MAX_PATH]{ 0 };

					res = RegEnumValueA(hKey, dwIndex, szValueName, &dwValueLen, 0, nullptr, nullptr, nullptr);
					if (ERROR_SUCCESS != res)
						break;

					if (szValueName[0] != '\0')
						vKeyList.push_back(szValueName);
					dwIndex++;
				}

				RegCloseKey(hKey);
			}
		}

		char szExecutable[MAX_PATH] = { 0 };	
		GetModuleFileNameA(nullptr, szExecutable, MAX_PATH);

		for (auto stCurrExecutable : vKeyList)
		{
			std::transform(stCurrExecutable.begin(), stCurrExecutable.end(), stCurrExecutable.begin(), tolower);

			CLogManager::Instance().Log(LL_SYS, fmt::format("Compat mode applied executable: {0}", stCurrExecutable.c_str()));

			if (!StrCmpICA(stCurrExecutable.c_str(), szExecutable))
				return true;

			if (stCurrExecutable.find(stAppName) != std::string::npos)
				return true;
		}

		return false;
	}
	bool CUtilites::IsKernelDebuggerEnabled()
	{
		static const auto hNtdll = LoadLibraryA("ntdll.dll");
		if (!hNtdll)
			return false;

		typedef NTSTATUS(NTAPI* TNtQuerySystemInformation)(WinAPI::SYSTEM_INFORMATION_CLASS SystemInformationClass, PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength);
		const auto NtQuerySystemInformation = reinterpret_cast<TNtQuerySystemInformation>(GetProcAddress(hNtdll, "NtQuerySystemInformation"));
		if (!NtQuerySystemInformation)
			return false;

		WinAPI::SYSTEM_KERNEL_DEBUGGER_INFORMATION pSKDI = { 0 };
		if (NT_SUCCESS(NtQuerySystemInformation(WinAPI::SystemKernelDebuggerInformation, &pSKDI, sizeof(pSKDI), NULL)))
		{
			if (pSKDI.KernelDebuggerEnabled && !pSKDI.KernelDebuggerNotPresent)
				return true;
		}
		return false;
	}
	bool CUtilites::IsSecureBootDisabled()
	{
		static const auto hNtdll = LoadLibraryA("ntdll.dll");
		if (!hNtdll)
			return false;

		typedef NTSTATUS(NTAPI* TNtQuerySystemInformation)(WinAPI::SYSTEM_INFORMATION_CLASS SystemInformationClass, PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength);
		const auto NtQuerySystemInformation = reinterpret_cast<TNtQuerySystemInformation>(GetProcAddress(hNtdll, "NtQuerySystemInformation"));
		if (!NtQuerySystemInformation)
			return false;

		auto dwcbSz = 0UL;

		WinAPI::SYSTEM_BOOT_ENVIRONMENT_INFORMATION sbei = { 0 };
		auto ntStat = NtQuerySystemInformation(WinAPI::SystemBootEnvironmentInformation, &sbei, sizeof(sbei), &dwcbSz);
		if (NT_SUCCESS(ntStat))
		{
			if (sbei.FirmwareType != FirmwareTypeUefi)
			{
				CLogManager::Instance().Log(LL_SYS, fmt::format("System firmware type: {0} is not uefi, secure boot check skipped.", sbei.FirmwareType));
				return false;
			}
		}

		WinAPI::SYSTEM_SECUREBOOT_INFORMATION ssbi = { 0 };
		ntStat = NtQuerySystemInformation(WinAPI::SystemSecureBootInformation, &ssbi, sizeof(ssbi), &dwcbSz);
		if (NT_SUCCESS(ntStat))
		{
			if (ssbi.SecureBootCapable && !ssbi.SecureBootEnabled)
				return true;
		}

		return false;
	}
	bool CUtilites::IsTestSignEnabled()
	{
		static const auto hNtdll = LoadLibraryA("ntdll.dll");
		if (!hNtdll)
			return false;

		typedef NTSTATUS(NTAPI* TNtQuerySystemInformation)(WinAPI::SYSTEM_INFORMATION_CLASS SystemInformationClass, PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength);
		const auto NtQuerySystemInformation = reinterpret_cast<TNtQuerySystemInformation>(GetProcAddress(hNtdll, "NtQuerySystemInformation"));
		if (!NtQuerySystemInformation)
			return false;
		
		WinAPI::SYSTEM_CODEINTEGRITY_INFORMATION sci = { 0 };
		sci.Length = sizeof(sci);

		auto dwcbSz = 0UL;
		const auto ntStat = NtQuerySystemInformation(WinAPI::SystemCodeIntegrityInformation, &sci, sizeof(sci), &dwcbSz);
		if (!NT_SUCCESS(ntStat))
			return false;

		return !!(sci.CodeIntegrityOptions & CODEINTEGRITY_OPTION_TESTSIGN);
	}
	bool CUtilites::IsCustomKernelSignersAllowed()
	{
		static const auto hNtdll = LoadLibraryA("ntdll.dll");
		if (!hNtdll)
			return false;
		
		typedef VOID(NTAPI* TRtlInitUnicodeString)(WinAPI::PUNICODE_STRING DestinationString, PCWSTR SourceString);
		typedef NTSTATUS(NTAPI* TNtQueryLicenseValue)(WinAPI::PUNICODE_STRING ValueName, PULONG Type, PVOID Data, ULONG DataSize, PULONG ResultDataSize);

		const auto RtlInitUnicodeString = reinterpret_cast<TRtlInitUnicodeString>(GetProcAddress(hNtdll, "RtlInitUnicodeString"));
		if (!RtlInitUnicodeString)
			return false;
		const auto NtQueryLicenseValue = reinterpret_cast<TNtQueryLicenseValue>(GetProcAddress(hNtdll, "NtQueryLicenseValue"));
		if (!NtQueryLicenseValue)
			return false;

		auto IsPolicyEnabled = [&](const std::wstring& wstPolicyName) {
			WinAPI::UNICODE_STRING usLicenseValue;
			RtlInitUnicodeString(&usLicenseValue, wstPolicyName.c_str());

			ULONG PolicyValueType = 0, CiAcpCks = 0, ReturnLength = 0;
			const auto ntStatus = NtQueryLicenseValue(&usLicenseValue, &PolicyValueType, (PVOID)&CiAcpCks, sizeof(CiAcpCks), &ReturnLength);
			if (!NT_SUCCESS(ntStatus))
			{
				CLogManager::Instance().Log(LL_ERR, fmt::format("NtQueryLicenseValue failed with status: {0}", fmt::ptr(reinterpret_cast<void*>(ntStatus))));
				return false;
			}

			if (PolicyValueType != REG_DWORD || ReturnLength != sizeof(ULONG))
			{
				CLogManager::Instance().Log(LL_ERR, fmt::format("Object type mismatch: {0} != {1} Return length: {2} != {3}", PolicyValueType, REG_DWORD, ReturnLength, sizeof(ULONG)));
				return false;
			}

			return CiAcpCks != 0;
		};

		if (IsPolicyEnabled(L"CodeIntegrity-AllowConfigurablePolicy"))
		{
			if (IsPolicyEnabled(L"CodeIntegrity-AllowConfigurablePolicy-CustomKernelSigners"))
			{
				CLogManager::Instance().Log(LL_ERR, "Custom signer policy is enabled!");
				return true;
			}
		}

		return false;
	}
}
