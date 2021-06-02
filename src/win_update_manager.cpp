#include "../include/pch.hpp"
#include "../include/win_update_manager.hpp"
#include "../include/com_error.hpp"
#include "../include/log_manager.hpp"

namespace SystemHealthCheck
{
	volatile bool g_vbSearchCompleted = false;

	DWORD WINAPI TimeoutThreadRoutine(LPVOID)
	{
		Sleep(50000);

		if (!g_vbSearchCompleted)
		{
			CLogManager::Instance().Log(LL_CRI, "Windows update search timeout!");
			std::exit(EXIT_FAILURE);
		}

		return 0;
	}


	CWinUpdateManager::CWinUpdateManager() :
		m_pUpdateSession2(nullptr), m_pSystemInfo(nullptr), m_pUpdateSearcher(nullptr), m_pUpdateList(nullptr)
	{
	}
	CWinUpdateManager::~CWinUpdateManager()
	{
	}

	void CWinUpdateManager::Release()
	{
		SAFE_RELEASE(m_pUpdateSession2);
		SAFE_RELEASE(m_pSystemInfo);
		SAFE_RELEASE(m_pUpdateSearcher);
		SAFE_RELEASE(m_pUpdateList);

		CoUninitialize();
	}

	bool CWinUpdateManager::Initialize()
	{
		auto bRet = false;

		// Initialize COM
		auto hr = CoInitializeEx(NULL, COINIT_MULTITHREADED);
		if (FAILED(hr))
		{
			CLogManager::Instance().Log(LL_ERR, fmt::format("CoInitialize failed with error: {0} {1}", fmt::ptr(reinterpret_cast<void*>(hr)), ComErrorMessage(hr)));
			return false;
		}

		// Create update session instance
		hr = CoCreateInstance(CLSID_UpdateSession, NULL, CLSCTX_INPROC_SERVER, IID_IUpdateSession2, (LPVOID*)&m_pUpdateSession2);
		if (FAILED(hr) || !m_pUpdateSession2)
		{
			CLogManager::Instance().Log(LL_ERR, fmt::format("CoCreateInstance(IID_IUpdateSession2) failed with error: {0} {1}", fmt::ptr(reinterpret_cast<void*>(hr)), ComErrorMessage(hr)));
			return false;
		}

		// Set default language
		const auto english_id = MAKELCID(MAKELANGID(LANG_ENGLISH, SUBLANG_ENGLISH_US), SORT_DEFAULT);
		hr = m_pUpdateSession2->put_UserLocale(english_id);
		if (FAILED(hr))
		{
			CLogManager::Instance().Log(LL_ERR, fmt::format("m_pUpdateSession2(put_UserLocale) failed with error: {0} {1}", fmt::ptr(reinterpret_cast<void*>(hr)), ComErrorMessage(hr)));
			return false;
		}

		// Check current status
		hr = CoCreateInstance(CLSID_SystemInformation, NULL, CLSCTX_INPROC_SERVER, IID_ISystemInformation, (void**)&m_pSystemInfo);
		if (FAILED(hr) || !m_pSystemInfo)
		{
			CLogManager::Instance().Log(LL_ERR, fmt::format("CoCreateInstance(IID_ISystemInformation) failed with error: {0} {1}", fmt::ptr(reinterpret_cast<void*>(hr)), ComErrorMessage(hr)));
			return false;
		}

		VARIANT_BOOL vbIsRebootRequired;
		hr = m_pSystemInfo->get_RebootRequired(&vbIsRebootRequired);
		if (FAILED(hr))
		{
			CLogManager::Instance().Log(LL_ERR, fmt::format("m_pSystemInfo->get_RebootRequired failed with error: {0} {1}", fmt::ptr(reinterpret_cast<void*>(hr)), ComErrorMessage(hr)));
			return false;
		}

		if (vbIsRebootRequired == VARIANT_TRUE)
		{
			CLogManager::Instance().Log(LL_ERR, fmt::format("Reboot required for continue to check for Windows updates."));
			return false;
		}

		return true;
	}

	bool CWinUpdateManager::HasAnyUpdate()
	{
		CLogManager::Instance().Log(LL_SYS, "Checking for available Windows updates...");

		// Searcher routine
		auto hr = m_pUpdateSession2->CreateUpdateSearcher(&m_pUpdateSearcher);
		if (FAILED(hr) || !m_pUpdateSearcher)
		{
			CLogManager::Instance().Log(LL_ERR, fmt::format("CreateUpdateSearcher failed with error: {0} {1}", fmt::ptr(reinterpret_cast<void*>(hr)), ComErrorMessage(hr)));
			return true;
		}

		hr = m_pUpdateSearcher->put_ServerSelection(ssWindowsUpdate);
		if (FAILED(hr))
		{
			CLogManager::Instance().Log(LL_ERR, fmt::format("put_ServerSelection failed with error: {0} {1}", fmt::ptr(reinterpret_cast<void*>(hr)), ComErrorMessage(hr)));
			return true;
		}

		hr = m_pUpdateSearcher->put_Online(VARIANT_TRUE);
		if (FAILED(hr))
		{
			CLogManager::Instance().Log(LL_ERR, fmt::format("put_Online failed with error: {0} {1}", fmt::ptr(reinterpret_cast<void*>(hr)), ComErrorMessage(hr)));
			return true;
		}

		const auto hTimeoutThread = CreateThread(nullptr, 0, TimeoutThreadRoutine, nullptr, 0, nullptr);
		if (!hTimeoutThread || hTimeoutThread == INVALID_HANDLE_VALUE)
		{
			CLogManager::Instance().Log(LL_ERR, fmt::format("CreateThread failed with error: {0}", GetLastError()));
			return true;
		}

		ISearchResult* results = nullptr;
		hr = m_pUpdateSearcher->Search(ComStr{ "IsInstalled=0 or IsHidden=1 or IsPresent=1" }, &results);
		if (FAILED(hr) || !results)
		{
			CLogManager::Instance().Log(LL_ERR, fmt::format("m_pUpdateSearcher->Search failed with error: {0} {1}", fmt::ptr(reinterpret_cast<void*>(hr)), ComErrorMessage(hr)));
			return true;
		}

		g_vbSearchCompleted = true;
		CloseHandle(hTimeoutThread);

		hr = results->get_Updates(&m_pUpdateList);
		if (FAILED(hr))
		{
			CLogManager::Instance().Log(LL_ERR, fmt::format("results->get_Updates failed with error: {0} {1}", fmt::ptr(reinterpret_cast<void*>(hr)), ComErrorMessage(hr)));
			return true;
		}

		LONG lTotalUpdateSize = 0;
		hr = m_pUpdateList->get_Count(&lTotalUpdateSize);
		if (FAILED(hr))
		{
			CLogManager::Instance().Log(LL_ERR, fmt::format("update_list->get_Count failed with error: {0} {1}", fmt::ptr(reinterpret_cast<void*>(hr)), ComErrorMessage(hr)));
			return true;
		}
		
		for (LONG i = 0; i < lTotalUpdateSize; i++)
		{
			IUpdate* pUpdateItem = nullptr;

			hr = m_pUpdateList->get_Item(i, &pUpdateItem);
			if (FAILED(hr) || !pUpdateItem)
			{
				CLogManager::Instance().Log(LL_ERR, fmt::format("update_list->get_Item failed with error: {0} {1}", fmt::ptr(reinterpret_cast<void*>(hr)), ComErrorMessage(hr)));
				continue;
			}

			BSTR updateName;
			hr = pUpdateItem->get_Title(&updateName);
			if (FAILED(hr))
			{
				CLogManager::Instance().Log(LL_ERR, fmt::format("update_item->get_Title failed with error: {0} {1}", fmt::ptr(reinterpret_cast<void*>(hr)), ComErrorMessage(hr)));
				continue;
			}

			VARIANT_BOOL vbIsInstalled;
			hr = pUpdateItem->get_IsInstalled(&vbIsInstalled);
			if (FAILED(hr))
			{
				CLogManager::Instance().Log(LL_ERR, fmt::format("update_item->get_IsInstalled failed with error: {0} {1}", fmt::ptr(reinterpret_cast<void*>(hr)), ComErrorMessage(hr)));
				continue;
			}

			VARIANT_BOOL vbIsMandatory;
			hr = pUpdateItem->get_IsMandatory(&vbIsMandatory);
			if (FAILED(hr))
			{
				CLogManager::Instance().Log(LL_ERR, fmt::format("update_item->get_IsMandatory failed with error: {0} {1}", fmt::ptr(reinterpret_cast<void*>(hr)), ComErrorMessage(hr)));
				continue;
			}

			CLogManager::Instance().Log(LL_SYS,
				fmt::format(L"An update found! Name: '{0}' Installed: {1} Mandatory: {2}",
					updateName, __VariantBoolToBool(vbIsInstalled), __VariantBoolToBool(vbIsMandatory)
				)
			);

			if (vbIsInstalled != VARIANT_TRUE && vbIsMandatory == VARIANT_TRUE)
			{
				SAFE_RELEASE(pUpdateItem);
				return true;
			}

			SAFE_RELEASE(pUpdateItem);
		}

		return false;
	}
}
