#pragma once
#include "abstract_singleton.hpp"

namespace SystemHealthCheck
{
	struct SRedirectedIOPipeCtx
	{
		wchar_t wszAppPath[MAX_PATH]{ L'\0' };
		wchar_t wszCmdLine[MAX_PATH]{ L'\0' };
		LPVOID lpSecurityDescriptor{ nullptr };

		SRedirectedIOPipeCtx(const std::wstring& wstAppPath, const std::wstring& wstCmdLine, LPSECURITY_ATTRIBUTES lpSecAttr)
		{
			if (!wstAppPath.empty())
				wcsncpy_s(wszAppPath, wstAppPath.c_str(), wstAppPath.size());

			if (!wstCmdLine.empty())
				wcsncpy_s(wszCmdLine, wstCmdLine.c_str(), wstCmdLine.size());

			lpSecurityDescriptor = lpSecAttr;
		}
	};

	class CRedirectedIOPipe : public CSingleton <CRedirectedIOPipe>
	{
	public:
		CRedirectedIOPipe(std::shared_ptr <SRedirectedIOPipeCtx> spPipeCtx);
		virtual ~CRedirectedIOPipe();

		bool Initialize(bool bUnicode = false);
		void Release();

		bool RunCommand(std::string& stCommand, bool bPrintRet = true);

	protected:
		bool __CheckPipeHasOutput(uint32_t nTimeout);
		bool __FixCommandOutput(std::string& stBuffer);
		bool __Read(std::string& stBuffer);
		bool __ReadAndPrint();
		bool __Write(const std::string& stBuffer);

	private:
		std::shared_ptr <SRedirectedIOPipeCtx> m_spClientCtx;

		bool m_bUnicode;
		bool m_bFirstExec;
		HANDLE m_hConsoleProc;
		std::string m_stLastCommand;

		HANDLE m_hInReadPipe;
		HANDLE m_hInWritePipe;
		HANDLE m_hOutReadPipe;
		HANDLE m_hOutWritePipe;
	};
}
