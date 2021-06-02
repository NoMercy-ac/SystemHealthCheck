#include "../include/pch.hpp"
#include "../include/amsi_scanner.hpp"
#include "../include/log_manager.hpp"
#include "../include/utilities.hpp"

#define EICAR "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"

namespace SystemHealthCheck
{
	CAMSIScanManager::CAMSIScanManager() :
		m_pkAmsiSession(nullptr), m_bInitialized(false)
	{
		ZeroMemory(&m_pkRefAmsiContext, sizeof(m_pkRefAmsiContext));
	}
	CAMSIScanManager::~CAMSIScanManager()
	{
	}

	void CAMSIScanManager::Release()
	{
		if (m_bInitialized)
		{
			AmsiCloseSession(m_pkRefAmsiContext, m_pkAmsiSession);
			if (m_pkRefAmsiContext)
				AmsiUninitialize(m_pkRefAmsiContext);
		}

		CoUninitialize();
	}

	bool CAMSIScanManager::Initialize()
	{
		auto hr = CoInitializeEx(0, COINIT_MULTITHREADED);
		if (FAILED(hr))
		{
			CLogManager::Instance().Log(LL_ERR, fmt::format("CoInitializeEx failed with status: {0}", fmt::ptr(reinterpret_cast<void*>(hr))));
			return false;
		}

		hr = AmsiInitialize(L"SystemHealthCheckAMSI", &m_pkRefAmsiContext);
		if (FAILED(hr))
		{
			CLogManager::Instance().Log(LL_ERR, fmt::format("AmsiInitialize failed with status: {0}", fmt::ptr(reinterpret_cast<void*>(hr))));
			if (hr == 0x80070103) // Windows Defender not working or nut supporing AMSI
				return true;
			return false;
		}

		hr = AmsiOpenSession(m_pkRefAmsiContext, &m_pkAmsiSession);
		if (FAILED(hr) || !m_pkAmsiSession)
		{
			CLogManager::Instance().Log(LL_ERR, fmt::format("AmsiOpenSession failed with status: {0}", fmt::ptr(reinterpret_cast<void*>(hr))));
			return false;
		}

		m_bInitialized = true;
		return true;
	}

	bool CAMSIScanManager::ScanSystem()
	{
		// Get debug privilege
		if (!CUtilites::Instance().EnablePrivilege("SeDebugPrivilege"))
		{
			CLogManager::Instance().Log(LL_ERR, "Enable debug privilege failed!");
			return false;
		}

		// Disable FS redirection
		PVOID OldValue = nullptr;
		if (!CUtilites::Instance().ManageFsRedirection(true, nullptr, &OldValue))
		{
			CLogManager::Instance().Log(LL_ERR, fmt::format("File redirection disable failed with error: {0}", GetLastError()));
			return false;
		}

		// Scan running processes
		{
			DWORD arProcesses[1024], cbNeeded;
			if (!EnumProcesses(arProcesses, sizeof(arProcesses), &cbNeeded))
			{
				CLogManager::Instance().Log(LL_ERR, fmt::format("EnumProcesses failed with error: {0}", GetLastError()));
				CUtilites::Instance().ManageFsRedirection(false, OldValue, nullptr);
				return false;
			}

			for (auto i = 0U; i < cbNeeded / sizeof(DWORD); i++)
			{
				if (arProcesses[i])
				{
					const auto hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, arProcesses[i]);
					if (!hProcess || hProcess == INVALID_HANDLE_VALUE)
					{
						CLogManager::Instance().Log(LL_WARN, fmt::format("OpenProcess ({0}) failed with error: {1}", arProcesses[i], GetLastError()));
						continue;
					}

					DWORD dwBufferSize = 1024;
					wchar_t wszBuffer[1024] = { L'\0' };
					if (!QueryFullProcessImageNameW(hProcess, 0, wszBuffer, &dwBufferSize))
					{
						CLogManager::Instance().Log(LL_WARN, fmt::format("QueryFullProcessImageNameW ({0}) failed with error: {1}", arProcesses[i], GetLastError()));
						CloseHandle(hProcess);
						continue;
					}

					if (this->IsMaliciousFile(wszBuffer))
					{
						CLogManager::Instance().Log(LL_ERR, fmt::format(L"Malicious file detected: ({0})", wszBuffer));
						CUtilites::Instance().ManageFsRedirection(false, OldValue, nullptr);
						return false;
					}

					CloseHandle(hProcess);
				}
			}
		}

		// Scan current directory
		wchar_t wszCurrDir[MAX_PATH] = { L'\0' };
		if (!GetCurrentDirectoryW(MAX_PATH, wszCurrDir))
		{
			CLogManager::Instance().Log(LL_ERR, fmt::format("GetCurrentDirectoryW failed with error: {0}", GetLastError()));
			CUtilites::Instance().ManageFsRedirection(false, OldValue, nullptr);
			return false;
		}

		for (const auto& entry : std::filesystem::recursive_directory_iterator(wszCurrDir))
		{
			if (!entry.is_regular_file())
				continue;

			if (this->IsMaliciousFile(entry.path().wstring()))
			{
				CLogManager::Instance().Log(LL_ERR, fmt::format(L"Malicious file detected: ({0})", entry.path().wstring()));
				CUtilites::Instance().ManageFsRedirection(false, OldValue, nullptr);
				return false;
			}
		}

		// Scan system directories
		wchar_t wszWinDir[MAX_PATH] = { L'\0' };
		if (!GetWindowsDirectoryW(wszCurrDir, MAX_PATH))
		{
			CLogManager::Instance().Log(LL_ERR, fmt::format("GetCurrentDirectoryW failed with error: {0}", GetLastError()));
			CUtilites::Instance().ManageFsRedirection(false, OldValue, nullptr);
			return false;
		}

		const auto wstSystem32 = fmt::format(L"{0}\\System32", wszCurrDir);
		for (const auto& entry : std::filesystem::directory_iterator(wstSystem32))
		{
			if (!entry.is_regular_file())
				continue;

			if (entry.path().extension() != ".dll" && entry.path().extension() != ".exe")
				continue;

			if (this->IsMaliciousFile(entry.path().wstring()))
			{
				CLogManager::Instance().Log(LL_ERR, fmt::format(L"Malicious file detected: ({0})", entry.path().wstring()));
				CUtilites::Instance().ManageFsRedirection(false, OldValue, nullptr);
				return false;
			}
		}

		const auto wstWow64 = fmt::format(L"{0}\\SysWOW64", wszCurrDir);
		for (const auto& entry : std::filesystem::directory_iterator(wstWow64))
		{
			if (!entry.is_regular_file())
				continue;

			if (entry.path().extension() != ".dll" && entry.path().extension() != ".exe")
				continue;
			
			if (this->IsMaliciousFile(entry.path().wstring()))
			{
				CLogManager::Instance().Log(LL_ERR, fmt::format(L"Malicious file detected: ({0})", entry.path().wstring()));
				CUtilites::Instance().ManageFsRedirection(false, OldValue, nullptr);
				return false;
			}
		}

		// Revert FS redirection
		CUtilites::Instance().ManageFsRedirection(false, OldValue, nullptr);
		return true;
	}

	bool CAMSIScanManager::IsMaliciousFile(const std::wstring& wstScanFile)
	{
		if (wstScanFile.empty())
			return false;

		if (std::find(m_vScannedFiles.begin(), m_vScannedFiles.end(), wstScanFile) != m_vScannedFiles.end())
			return false;
		m_vScannedFiles.emplace_back(wstScanFile);

#ifdef _DEBUG
		CLogManager::Instance().Log(LL_SYS, fmt::format(L"File ({0}) scan started!", wstScanFile));
#endif

		if (!std::filesystem::exists(wstScanFile))
		{
			CLogManager::Instance().Log(LL_ERR, fmt::format(L"File: ({0}) does not exist!", wstScanFile));
			return true;
		}

		auto spFileCtx = std::make_shared<SFileReadCtx>();
		if (!this->__GetFileContext(wstScanFile, spFileCtx))
		{
			CLogManager::Instance().Log(LL_ERR, fmt::format(L"__GetFileContext ({0}) failed!", wstScanFile));
			return false;
		}

		const auto spScanRet = this->__ScanFile(wstScanFile, spFileCtx);
		if (!spScanRet || !spScanRet.get())
		{
			CLogManager::Instance().Log(LL_ERR, fmt::format(L"__ScanFile ({0}) failed!", wstScanFile));
			return false;
		}

		VirtualFree(spFileCtx->lpBuffer, 0, MEM_RELEASE);

		if (spScanRet->bIsMalware)
			CLogManager::Instance().Log(LL_WARN, fmt::format(L"Malicious file detected: {0} Level: {1} ({2})", wstScanFile, spScanRet->hrRiskLevel, this->__GetResultDescription(spScanRet->hrRiskLevel)));

#ifdef _DEBUG
		CLogManager::Instance().Log(LL_SYS, fmt::format(L"File ({0}) scan completed!", wstScanFile));
#endif
		return spScanRet->bIsMalware;
	}

	std::shared_ptr <SAmsiScanResult> CAMSIScanManager::__ScanFile(const std::wstring& wstFileName, const std::shared_ptr <SFileReadCtx>& spFileCtx)
	{
		if (!spFileCtx || !spFileCtx.get() || !spFileCtx->lpBuffer || !spFileCtx->dwSize)
		{
			CLogManager::Instance().Log(LL_ERR, "AMSI Scan file sanity check failed!");
			return {};
		}

		AMSI_RESULT res;
		const auto hr = AmsiScanBuffer(m_pkRefAmsiContext, spFileCtx->lpBuffer, spFileCtx->dwSize, wstFileName.c_str(), m_pkAmsiSession, &res);
		if (FAILED(hr))
		{
			CLogManager::Instance().Log(LL_ERR, fmt::format("AmsiScanBuffer failed with status: {0}", fmt::ptr(reinterpret_cast<void*>(hr))));
			return {};
		}

		const auto spScanResult = std::make_shared<SAmsiScanResult>();
		spScanResult->hrRiskLevel = res;
		spScanResult->bIsMalware = AmsiResultIsMalware(res);
		return spScanResult;
	}

	bool CAMSIScanManager::__GetFileContext(const std::wstring& wstFileName, std::shared_ptr <SFileReadCtx>& spFileCtx)
	{
		const auto hFile = CreateFileW(wstFileName.c_str(), GENERIC_READ, 0, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
		if (!hFile || hFile == INVALID_HANDLE_VALUE)
		{
			CLogManager::Instance().Log(LL_ERR, fmt::format(L"CreateFileW ({0}) failed with error: {1}", wstFileName, GetLastError()));
			return false;
		}

		const auto dwFileSize = GetFileSize(hFile, nullptr);
		if (!dwFileSize || dwFileSize == INVALID_FILE_SIZE)
		{
			CLogManager::Instance().Log(LL_ERR, fmt::format(L"GetFileSize ({0}) failed with error: {1}", wstFileName, GetLastError()));
			CloseHandle(hFile);
			return false;
		}

		const auto lpBuffer = (BYTE*)VirtualAlloc(nullptr, dwFileSize, MEM_COMMIT, PAGE_READWRITE);
		if (!lpBuffer)
		{
			CLogManager::Instance().Log(LL_ERR, fmt::format("VirtualAlloc ({0}) failed with error: {1}", dwFileSize, GetLastError()));
			CloseHandle(hFile);
			return false;
		}

		DWORD dwBytesRead = 0;
		if (!ReadFile(hFile, lpBuffer, dwFileSize, &dwBytesRead, nullptr))
		{
			CLogManager::Instance().Log(LL_ERR, fmt::format(L"ReadFile ({0}) failed with error: {1}", wstFileName, GetLastError()));
			CloseHandle(hFile);
			VirtualFree(lpBuffer, 0, MEM_RELEASE);
			return false;
		}

		if (spFileCtx && spFileCtx.get())
		{
			spFileCtx->lpBuffer = lpBuffer;
			spFileCtx->dwSize = dwFileSize;
		}

		CloseHandle(hFile);
		return true;
	}

	std::wstring CAMSIScanManager::__GetResultDescription(HRESULT hrScore)
	{
		std::wstring wstDescription;

		switch (hrScore)
		{
			case AMSI_RESULT_CLEAN:
				wstDescription = L"File is clean";
				break;
			case AMSI_RESULT_NOT_DETECTED:
				wstDescription = L"No threat detected";
				break;
			case AMSI_RESULT_BLOCKED_BY_ADMIN_START:
				wstDescription = L"Threat is blocked by the administrator";
				break;
			case AMSI_RESULT_BLOCKED_BY_ADMIN_END:
				wstDescription = L"Threat is blocked by the administrator";
				break;
			case AMSI_RESULT_DETECTED:
				wstDescription = L"File is considered malware";
				break;
			default:
				wstDescription = fmt::format(L"Unknown: {0}", fmt::ptr(reinterpret_cast<void*>(hrScore)));
				break;
		}

		return wstDescription;
	}
}
