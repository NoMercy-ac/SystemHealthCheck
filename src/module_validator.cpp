#include "../include/pch.hpp"
#include "../include/module_validator.hpp"
#include "../include/log_manager.hpp"
#include "../include/utilities.hpp"

namespace SystemHealthCheck
{
	CModuleValidator::CModuleValidator() :
		m_hImageHlp(nullptr), m_hSFC(nullptr), m_fnCheckSumMappedFile(nullptr), m_fnSfcIsFileProtected(nullptr)
	{
	}
	CModuleValidator::~CModuleValidator()
	{
	}

	void CModuleValidator::Release()
	{
		m_lstSystemModules.clear();

		FreeLibrary(m_hSFC);
		FreeLibrary(m_hImageHlp);
	}

	bool CModuleValidator::Initialize()
	{
		m_lstSystemModules = {
			L"Kernel32.dll",
			L"Ntdll.dll",
			L"User32.dll",
			L"Psapi.dll",
			L"Dbghelp.dll",
			L"Kernelbase.dll",
			L"Advapi32.dll",
			L"Wininet.dll",
			L"Winsta.dll",
			L"Shlwapi.dll",
			L"Shell32.dll",
			L"Crypt32.dll",
			L"Ws2_32.dll",
			L"Iphlpapi.dll",
			L"Mpr.dll",
			L"Wintrust.dll",
			L"Dnsapi.dll",
			L"Ole32.dll",
			L"GdiPlus.dll",
			L"Gdi32.dll",
			L"UserEnv.dll",
			L"Winmm.dll",
			L"Win32u.dll",
			L"Imagehlp.dll",
			L"Wevtapi.dll",
			L"Sfc.dll",
			L"Netapi32.dll",
			L"MsCoree.dll",
			L"WindowsCodecs.dll",
			L"Msimg32.dll",
			L"Wtsapi32.dll",
			L"Setupapi.dll",
			L"Inetmib1.dll",
			L"Snmpapi.dll",
			L"Version.dll",
			L"Srclient.dll",
			L"OleAut32.dll",
			L"TDH.dll",
			L"Fltlib.dll"
		};

		m_hSFC = LoadLibraryA("sfc.dll");
		if (!m_hSFC)
		{
			CLogManager::Instance().Log(LL_ERR, fmt::format("LoadLibraryA (sfc) failed with error: {0}", GetLastError()));
			return false;
		}

		m_hImageHlp = LoadLibraryA("imagehlp.dll");
		if (!m_hImageHlp)
		{
			CLogManager::Instance().Log(LL_ERR, fmt::format("LoadLibraryA (imagehlp) failed with error: {0}", GetLastError()));
			return false;
		}

		m_fnSfcIsFileProtected = reinterpret_cast<TSfcIsFileProtected>(GetProcAddress(m_hSFC, "SfcIsFileProtected"));
		if (!m_fnSfcIsFileProtected)
		{
			CLogManager::Instance().Log(LL_ERR, fmt::format("GetProcAddress (sfc) failed with error: {0}", GetLastError()));
			return false;
		}

		m_fnCheckSumMappedFile = reinterpret_cast<TCheckSumMappedFile>(GetProcAddress(m_hImageHlp, "CheckSumMappedFile"));
		if (!m_fnCheckSumMappedFile)
		{
			CLogManager::Instance().Log(LL_ERR, fmt::format("GetProcAddress (imagehlp) failed with error: {0}", GetLastError()));
			return false;
		}

		return true;
	}

	bool CModuleValidator::ValidateSystemModules()
	{
		PVOID OldValue = nullptr;
		if (!CUtilites::Instance().ManageFsRedirection(true, nullptr, &OldValue))
		{
			CLogManager::Instance().Log(LL_ERR, fmt::format("File redirection disable failed with error: {0}", GetLastError()));
			return false;
		}

		wchar_t wszSysDir[MAX_PATH * 2] = { L'\0' };
		if (!GetSystemDirectoryW(wszSysDir, MAX_PATH))
		{
			CLogManager::Instance().Log(LL_ERR, fmt::format("GetSystemDirectoryW failed with error: {0}", GetLastError()));
			CUtilites::Instance().ManageFsRedirection(false, OldValue, nullptr);
			return false;
		}

		for (auto wstModuleFilename : m_lstSystemModules)
		{
			wstModuleFilename = fmt::format(L"{0}\\{1}", wszSysDir, wstModuleFilename);

#ifdef _DEBUG
			CLogManager::Instance().Log(LL_SYS, fmt::format(L"System module file: {0} checking...", wstModuleFilename));
#endif

			if (!std::filesystem::exists(wstModuleFilename))
			{
				CLogManager::Instance().Log(LL_ERR, fmt::format(L"System module file: {0} does not exist!", wstModuleFilename));
				break;
			}

			if (!CUtilites::Instance().IsFileDigitalSigned(wstModuleFilename))
			{
				CLogManager::Instance().Log(LL_WARN, fmt::format(L"System module file: {0} is not digital signed. Last error: {1}", wstModuleFilename, GetLastError()));
			}

			if (!m_fnSfcIsFileProtected(nullptr, wstModuleFilename.c_str()))
			{
				CLogManager::Instance().Log(LL_ERR, fmt::format(L"System module file: {0} could not validated by SFC API! Last error: {1}", wstModuleFilename, GetLastError()));
				break;
			}

			const auto pFileCtx = CUtilites::Instance().ReadFileContent(wstModuleFilename);
			if (!pFileCtx.lpBuffer || !pFileCtx.dwSize)
			{
				CLogManager::Instance().Log(LL_ERR, fmt::format(L"System module file: {0} read content failed!", wstModuleFilename));
				break;
			}

			DWORD dwHeaderSum = 0, dwChecksum = 0;
			if (!m_fnCheckSumMappedFile(pFileCtx.lpBuffer, pFileCtx.dwSize, &dwHeaderSum, &dwChecksum))
			{
				CLogManager::Instance().Log(LL_ERR, fmt::format(L"System module file: {0} getting checksum failed! Last error: {1}", wstModuleFilename, GetLastError()));
				free(pFileCtx.lpBuffer);
				break;
			}
			free(pFileCtx.lpBuffer);

			if (!dwHeaderSum || !dwChecksum || dwHeaderSum != dwChecksum)
			{
				CLogManager::Instance().Log(LL_ERR, fmt::format(L"System module file: {0} could not validated by PE!", wstModuleFilename));
				break;
			}

#ifdef _DEBUG
			CLogManager::Instance().Log(LL_SYS, fmt::format(L"System module file: {0} succesfully validated.", wstModuleFilename));
#endif
		}

		CUtilites::Instance().ManageFsRedirection(false, OldValue, nullptr);
		return true;
	}
}
