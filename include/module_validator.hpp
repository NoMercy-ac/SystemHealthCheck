#pragma once
#include "abstract_singleton.hpp"

namespace SystemHealthCheck
{
	typedef BOOL(WINAPI* TSfcIsFileProtected)(_In_opt_ HANDLE RpcHandle, _In_ LPCWSTR Path); // sfc
	typedef PIMAGE_NT_HEADERS(WINAPI* TCheckSumMappedFile)(_In_ PVOID BaseAddress, _In_ DWORD FileLength, _Out_ PDWORD HeaderSum, _Out_ PDWORD CheckSum); // imagehlp

	class CModuleValidator : public CSingleton <CModuleValidator>
	{
	public:
		CModuleValidator();
		virtual ~CModuleValidator();

		bool Initialize();
		void Release();

		bool ValidateSystemModules();

	private:
		std::list <std::wstring> m_lstSystemModules;

		HMODULE m_hSFC;
		HMODULE m_hImageHlp;

		TSfcIsFileProtected m_fnSfcIsFileProtected;
		TCheckSumMappedFile m_fnCheckSumMappedFile;
	};
}
