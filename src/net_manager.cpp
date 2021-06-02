#include "../include/pch.hpp"
#include "../include/net_manager.hpp"
#include "../include/firewall_helper.hpp"
#include "../include/log_manager.hpp"
#include "../include/utilities.hpp"

namespace SystemHealthCheck
{
	CNetworkManager::CNetworkManager()
	{
	}
	CNetworkManager::~CNetworkManager()
	{
	}

	void CNetworkManager::Release()
	{
	}

	bool CNetworkManager::Initialize()
	{
		// Check firewall rules
		CFirewallHelper fwMgr{};

		auto fwOn = false;
		if (SUCCEEDED(fwMgr.IsFirewallEnabled(fwOn)) && fwOn)
		{
			auto bExist = false;
			fwMgr.EnumerateRules([&](INetFwRule* pFwRule, void* pvUserContext) -> bool {
				const auto c_wszSearchData = reinterpret_cast<wchar_t*>(pvUserContext);

				BSTR bstrVal{};
				if (SUCCEEDED(pFwRule->get_Name(&bstrVal)))
				{
					if (StrStrIW(bstrVal, c_wszSearchData))
					{
						bExist = true;
						return true;
					}
				}
				return true;
			}, L"nomercy.ac");

			if (bExist)
			{
				CLogManager::Instance().Log(LL_ERR, "NoMercy.ac value detected in firewall rules!");
				return false;
			}
		}

		// Check hosts file
		wchar_t wszWinPath[MAX_PATH * 2] = { L'\0' };
		if (!GetWindowsDirectoryW(wszWinPath, MAX_PATH))
		{
			CLogManager::Instance().Log(LL_ERR, fmt::format("GetWindowsDirectoryW failed with error: {0}", GetLastError()));
			return false;
		}

		const auto wszHostsFile = fmt::format(L"{0}\\System32\\drivers\\etc\\hosts", wszWinPath);
		if (std::filesystem::exists(wszHostsFile))
		{
			const auto lpReadCtx = CUtilites::Instance().ReadFileContent(wszHostsFile);
			if (lpReadCtx.lpBuffer && lpReadCtx.dwSize)
			{
				const auto wstBuffer = std::wstring(reinterpret_cast<wchar_t*>(lpReadCtx.lpBuffer), lpReadCtx.dwSize);
				free(lpReadCtx.lpBuffer);

				if (StrStrIW(wstBuffer.c_str(), L"nomercy.ac"))
				{
					CLogManager::Instance().Log(LL_ERR, "NoMercy.ac value detected in hosts file!");
					return false;
				}
			}
		}

		return true;
	}

	bool CNetworkManager::CheckInternetStatus()
	{
		DWORD dwFlags = 0;
		if (!InternetGetConnectedState(&dwFlags, 0))
		{
			CLogManager::Instance().Log(LL_ERR, fmt::format("InternetGetConnectedState failed with error: {0} returned flags: {1}", GetLastError(), dwFlags));
			return false;
		}

		const auto dwTestConnectionRet = InternetAttemptConnect(0);
		if (dwTestConnectionRet != ERROR_SUCCESS)
		{
			CLogManager::Instance().Log(LL_ERR, fmt::format("InternetAttemptConnect failed with return: {0}", dwTestConnectionRet));
			return false;
		}

		if (!InternetCheckConnectionW(L"https://google.com", FLAG_ICC_FORCE_CONNECTION, 0))
		{
			CLogManager::Instance().Log(LL_ERR, fmt::format("InternetCheckConnectionW failed with error: {0}", GetLastError()));
			return false;
		}
		return true;
	}
	bool CNetworkManager::CheckNoMercyServerStatus()
	{
		if (!InternetCheckConnectionW(L"http://www.nomercy.ac", FLAG_ICC_FORCE_CONNECTION, 0))
		{
			CLogManager::Instance().Log(LL_ERR, fmt::format("InternetCheckConnectionW (WEB) failed with error: {0}", GetLastError()));
			return false;
		}
		if (!InternetCheckConnectionW(L"http://api.nomercy.ac", FLAG_ICC_FORCE_CONNECTION, 0))
		{
			CLogManager::Instance().Log(LL_ERR, fmt::format("InternetCheckConnectionW (API) failed with error: {0}", GetLastError()));
			return false;
		}
		if (!InternetCheckConnectionW(L"http://cdn.nomercy.ac", FLAG_ICC_FORCE_CONNECTION, 0))
		{
			CLogManager::Instance().Log(LL_ERR, fmt::format("InternetCheckConnectionW (CDN) failed with error: {0}", GetLastError()));
			return false;
		}
		return true;
	}
	bool CNetworkManager::CheckNoMercyVersion(uint32_t nCurrentVersion)
	{
		auto vTempdata = std::vector<uint8_t>();
		char szTempBuffer[4096] = { 0 };
		auto dwBytesRead = 0UL;

		const auto stAgentName = "SystemHealthCheck"s;
		const auto hInternet = InternetOpenA(stAgentName.c_str(), NULL, NULL, NULL, NULL);
		if (!hInternet)
		{
			CLogManager::Instance().Log(LL_ERR, fmt::format("InternetOpenA failed with error: {0}", GetLastError()));
			return false;
		}

		const auto stWebAddress = "https://www.nomercy.ac/api/min_ver"s;
		const auto hFile = InternetOpenUrlA(hInternet, stWebAddress.c_str(), NULL, NULL, INTERNET_FLAG_RELOAD | INTERNET_FLAG_DONT_CACHE, NULL);
		if (!hFile)
		{
			CLogManager::Instance().Log(LL_ERR, fmt::format("InternetOpenUrlA failed with error: {0}", GetLastError()));
			InternetCloseHandle(hInternet);
			return false;
		}

		auto dwAvailableBytes = 0UL;
		if (!InternetQueryDataAvailable(hFile, &dwAvailableBytes, 0, 0))
		{
			CLogManager::Instance().Log(LL_ERR, fmt::format("InternetQueryDataAvailable failed with error: {0}", GetLastError()));
			InternetCloseHandle(hInternet);
			InternetCloseHandle(hFile);
			return false;
		}

#ifdef _DEBUG
		CLogManager::Instance().Log(LL_SYS, fmt::format("Available byte count: {0}", dwAvailableBytes));
#endif

		if (!dwAvailableBytes)
		{
			CLogManager::Instance().Log(LL_ERR, "Have not any available data in remote version page");
			return false;
		}

		do {
			if (InternetReadFile(hFile, szTempBuffer, sizeof(szTempBuffer), &dwBytesRead))
				std::copy(&szTempBuffer[0], &szTempBuffer[dwBytesRead], std::back_inserter(vTempdata));
		} while (dwBytesRead);

		if (vTempdata.empty())
		{
			CLogManager::Instance().Log(LL_ERR, fmt::format("Any data could not read. Last Error: {0}", GetLastError()));
			InternetCloseHandle(hInternet);
			InternetCloseHandle(hFile);
			return false;
		}

		InternetCloseHandle(hInternet);
		InternetCloseHandle(hFile);

		std::string stRemoteData(vTempdata.begin(), vTempdata.end());
		CLogManager::Instance().Log(LL_SYS, fmt::format("Read remote version completed. Data: {0} Current version: {1}", stRemoteData, nCurrentVersion));

		if (stRemoteData.empty() || stRemoteData.size() > 10)
			return false;

		if (!CUtilites::Instance().IsContentNumber(stRemoteData))
			return false;

		const uint32_t c_nRemoteMinimumVersion = std::atoi(stRemoteData.c_str());
		if (nCurrentVersion < c_nRemoteMinimumVersion)
			return false;

		return true;
	}
}
