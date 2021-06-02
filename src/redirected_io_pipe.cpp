#include "../include/pch.hpp"
#include "../include/redirected_io_pipe.hpp"
#include "../include/log_manager.hpp"
#include "../include/simple_timer.hpp"
#include "../include/utilities.hpp"
#include <codecvt>
namespace SystemHealthCheck
{
	CRedirectedIOPipe::CRedirectedIOPipe(std::shared_ptr <SRedirectedIOPipeCtx> spPipeCtx) :
		m_bUnicode(false), m_bFirstExec(true), m_spClientCtx(std::move(spPipeCtx)), m_hConsoleProc(nullptr),
		m_hInReadPipe(nullptr), m_hInWritePipe(nullptr), m_hOutReadPipe(nullptr), m_hOutWritePipe(nullptr)
	{
	}
	CRedirectedIOPipe::~CRedirectedIOPipe()
	{
		this->Release();
	}

	void CRedirectedIOPipe::Release()
	{
		m_stLastCommand = "";
		m_bFirstExec = true;

		if (m_hConsoleProc)
		{
			TerminateProcess(m_hConsoleProc, EXIT_SUCCESS);
			m_hConsoleProc = nullptr;
		}

		if (m_hInReadPipe)
		{
			CloseHandle(m_hInReadPipe);
			m_hInReadPipe = nullptr;
		}

		if (m_hInWritePipe)
		{
			CloseHandle(m_hInWritePipe);
			m_hInWritePipe = nullptr;
		}

		if (m_hOutReadPipe)
		{
			CloseHandle(m_hOutReadPipe);
			m_hOutReadPipe = nullptr;
		}

		if (m_hOutWritePipe)
		{
			CloseHandle(m_hOutWritePipe);
			m_hOutWritePipe = nullptr;
		}
	}

	bool CRedirectedIOPipe::Initialize(bool bUnicode)
	{
		m_bUnicode = bUnicode;

		// Validate client context
		if (!m_spClientCtx)
		{
			CLogManager::Instance().Log(LL_ERR, "Client context is not valid!");
			return false;
		}

		// Close old process datas
		this->Release();

		// Create security attributes
		SECURITY_ATTRIBUTES sa = { 0 };
		sa.nLength = sizeof(SECURITY_ATTRIBUTES);
		sa.bInheritHandle = TRUE;
		sa.lpSecurityDescriptor = m_spClientCtx->lpSecurityDescriptor;

		// Create I/O pipes & Set inherit flag
		if (!CreatePipe(&m_hOutReadPipe, &m_hOutWritePipe, &sa, 0))
		{
			CLogManager::Instance().Log(LL_ERR, fmt::format("CreatePipe (1) failed with error: {0}", GetLastError()));
			return false;
		}

		if (!SetHandleInformation(m_hOutReadPipe, HANDLE_FLAG_INHERIT, 0))
		{
			CLogManager::Instance().Log(LL_ERR, fmt::format("SetHandleInformation (1) failed with error: {0}", GetLastError()));
			return false;
		}

		if (!CreatePipe(&m_hInReadPipe, &m_hInWritePipe, &sa, 0))
		{
			CLogManager::Instance().Log(LL_ERR, fmt::format("CreatePipe (2) failed with error: {0}", GetLastError()));
			return false;
		}

		if (!SetHandleInformation(m_hInWritePipe, HANDLE_FLAG_INHERIT, 0))
		{
			CLogManager::Instance().Log(LL_ERR, fmt::format("SetHandleInformation (2) failed with error: {0}", GetLastError()));
			return false;
		}

		// Disable file redirection
		PVOID OldValue = nullptr;
		if (!CUtilites::Instance().ManageFsRedirection(true, nullptr, &OldValue))
		{
			CLogManager::Instance().Log(LL_ERR, fmt::format("File redirection disable failed with error: {0}", GetLastError()));
			return false;
		}

		// Setup launch parameters
		PROCESS_INFORMATION pi = { 0 };

		STARTUPINFOW si = { 0 };
		si.cb = sizeof(si);
		si.wShowWindow = SW_HIDE;
		si.dwFlags |= STARTF_USESTDHANDLES;
		si.hStdError = m_hOutWritePipe;
		si.hStdOutput = m_hOutWritePipe;
		si.hStdInput = m_hInReadPipe;

		// Copy cmdline to new pointer
		auto wszCmdLine = new wchar_t[MAX_PATH];
		memset(wszCmdLine, 0, MAX_PATH * sizeof(wchar_t));

		if (m_spClientCtx->wszCmdLine[0] != L'\0')
			wcsncpy(wszCmdLine, m_spClientCtx->wszCmdLine, wcslen(m_spClientCtx->wszCmdLine));

		if (bUnicode)
		{
			const auto wszUnicodeFlag = L" /U"s;
			wcsncat(wszCmdLine, wszUnicodeFlag.c_str(), wszUnicodeFlag.size());
		}

		// Create child process
		const auto bSuccess = CreateProcessW(
			m_spClientCtx->wszAppPath[0] == L'\0' ? nullptr : m_spClientCtx->wszAppPath,
			wszCmdLine,
			nullptr, nullptr, TRUE, 0, nullptr, nullptr,
			&si, &pi
		);

		// Delete created mcdline ptr
		delete[] wszCmdLine;
		wszCmdLine = nullptr;

		// Revert file redirection
		CUtilites::Instance().ManageFsRedirection(false, OldValue, nullptr);

		// Check create result
		if (!bSuccess)
		{
			CLogManager::Instance().Log(LL_ERR, fmt::format(L"CreateProcessW('{0}' / '{1}') failed with error: {2}", m_spClientCtx->wszAppPath, m_spClientCtx->wszCmdLine, GetLastError()));
			return false;
		}
#ifdef _DEBUG
		CLogManager::Instance().Log(LL_SYS, fmt::format(L"Child process: '{0}' ('{1}') [{2}] created! Unicode: {3}", m_spClientCtx->wszAppPath, m_spClientCtx->wszCmdLine, pi.dwProcessId, m_bUnicode));
#endif

		// Save child process handle
		m_hConsoleProc = pi.hProcess;

		// Close not required handles
		CloseHandle(pi.hThread);
		return true;
	}

	bool CRedirectedIOPipe::RunCommand(std::string& stCommand, bool bPrintRet)
	{
		auto bRet = false;

		FileLogf(CUSTOM_LOG_HISTORY_FILENAME, "Command: %s execution started! Unicode: %d First: %d", stCommand.c_str(), m_bUnicode, m_bFirstExec);
		m_stLastCommand = stCommand;

		// Write command to pipe buffer
		if (!this->__Write(stCommand + "\n"))
			return bRet;

		// Give some exec time penalty
		if (!__CheckPipeHasOutput(30000))
		{
			CLogManager::Instance().Log(LL_ERR, "Pipe read timeout!");
			return bRet;
		}

		if (bPrintRet)
			bRet = this->__ReadAndPrint();
		else
			bRet = this->__Read(stCommand);

		m_bFirstExec = false;
		FileLogf(CUSTOM_LOG_HISTORY_FILENAME, "Command: execution completed with status: %d", bRet ? 1 : 0);
		return bRet;
	}

	bool CRedirectedIOPipe::__CheckPipeHasOutput(uint32_t nTimeout)
	{
		CSimpleTimer <std::chrono::milliseconds> timer;

		auto bRet = false;

		while (true)
		{
			Sleep(1000);

			if (timer.diff() > nTimeout)
				break;

			DWORD dwPipeBytesRead = 0;
			if (PeekNamedPipe(m_hOutReadPipe, nullptr, 0, nullptr, &dwPipeBytesRead, nullptr) && dwPipeBytesRead)
			{
				bRet = true;
				break;
			}
		}

		return bRet;
	}

	bool CRedirectedIOPipe::__FixCommandOutput(std::string& stBuffer)
	{
		if (stBuffer.empty())
			return false;
		
		if (m_bFirstExec)
		{
			// Start pos
			const auto stStartPosSign = ">" + m_stLastCommand + "\n";
			const auto spos = stBuffer.find(stStartPosSign);
			if (spos == std::string::npos)
				return false;
			if (stBuffer.size() < spos + stStartPosSign.size())
				return false;

			stBuffer = stBuffer.substr(spos + stStartPosSign.size(), stBuffer.size());

			// End pos
			const auto stEOLChar = "\r\n"s;
			const auto epos = stBuffer.find_last_of(stEOLChar);
			if (epos == std::string::npos)
				return false;
			if (stBuffer.size() < epos + stEOLChar.size())
				return false;

			stBuffer = stBuffer.substr(0, epos - stEOLChar.size());
		}
		else
		{
			const auto stStartPosSign = "\r\n"s;
			const auto spos = stBuffer.find_first_of(stStartPosSign);
			if (spos == std::string::npos)
				return false;
			if (stBuffer.size() < spos + stStartPosSign.size())
				return false;

			stBuffer = stBuffer.substr(spos, stBuffer.size());
		}

		return !stBuffer.empty();
	}

	bool CRedirectedIOPipe::__ReadAndPrint()
	{
		auto bRet = false;

		if (!m_hOutReadPipe || m_hOutReadPipe == INVALID_HANDLE_VALUE)
		{
			CLogManager::Instance().Log(LL_ERR, "Output read pipe is not valid!");
			return bRet;
		}

		FileLog(CUSTOM_LOG_HISTORY_FILENAME, "\n");

		DWORD dwPipeBytesReadTotal = 0;
		while (true)
		{
			DWORD dwDummy = 0;
			if (!GetHandleInformation(m_hOutReadPipe, &dwDummy))
			{
				CLogManager::Instance().Log(LL_ERR, "Output read pipe handle is corrupted!");
				break;
			}

			DWORD dwPipeBytesReadCurrent = 0;
			if (!PeekNamedPipe(m_hOutReadPipe, nullptr, 0, nullptr, &dwPipeBytesReadCurrent, nullptr))
			{
				CLogManager::Instance().Log(LL_ERR, fmt::format("PeekNamedPipe failed with error: {0}", GetLastError()));
				break;
			}

			dwPipeBytesReadTotal += dwPipeBytesReadCurrent;

			if (!dwPipeBytesReadTotal)
				break;

#ifdef _DEBUG
			CLogManager::Instance().Log(LL_SYS, fmt::format("Currently: {0} bytes is readable in pipe, Total: {1} bytes should read!", dwPipeBytesReadCurrent, dwPipeBytesReadTotal));
#endif

			auto nBufSize = dwPipeBytesReadTotal;
			auto pvBuffer = calloc(nBufSize, m_bUnicode ? sizeof(wchar_t) : sizeof(char));
			if (!pvBuffer)
			{
				CLogManager::Instance().Log(LL_ERR, fmt::format("Read buffer allocation with size: {0} is failed with error: {1}", nBufSize, errno));

				nBufSize = 2048;
				pvBuffer = calloc(nBufSize, m_bUnicode ? sizeof(wchar_t) : sizeof(char));
				if (!pvBuffer)
				{
					CLogManager::Instance().Log(LL_ERR, fmt::format("Read buffer allocation with size: {0} is failed with error: {1}", nBufSize, errno));
					break;
				}
			}
			memset(pvBuffer, 0, nBufSize);

			const auto dwReadSize = (dwPipeBytesReadTotal < nBufSize) ? dwPipeBytesReadTotal : nBufSize;
#ifdef _DEBUG
			CLogManager::Instance().Log(LL_SYS, fmt::format("Read buffer size: {0}", dwReadSize));
#endif

			DWORD dwFileBytesRead = 0;
			if (!ReadFile(m_hOutReadPipe, pvBuffer, dwReadSize, &dwFileBytesRead, nullptr))
			{
				CLogManager::Instance().Log(LL_ERR, fmt::format("ReadFile failed with read size: {0} error: {1}", dwFileBytesRead, GetLastError()));
				free(pvBuffer);
				break;
			}

			auto stBufferCopy = ""s;
			if (m_bUnicode)
			{
				const auto wstBufferCopy = std::wstring(reinterpret_cast<wchar_t*>(pvBuffer), dwFileBytesRead);
				stBufferCopy = CUtilites::Instance().ToAnsiString(wstBufferCopy);

#ifdef _DEBUG
				CLogManager::Instance().Log(LL_SYS, fmt::format(L"Read unicode buffer: {0}", wstBufferCopy));
#endif
			}
			else
			{
				stBufferCopy = std::string(reinterpret_cast<char*>(pvBuffer), dwFileBytesRead);
			}

#ifdef _DEBUG
			CLogManager::Instance().Log(LL_SYS, fmt::format("Read buffer: {0}", stBufferCopy));
#endif

			if (!__FixCommandOutput(stBufferCopy))
			{
				CLogManager::Instance().Log(LL_ERR, fmt::format("Read command output: {0} is not valid", stBufferCopy));
				free(pvBuffer);
				break;
			}

			FileLogf(CUSTOM_LOG_HISTORY_FILENAME, "%s\n", stBufferCopy.c_str());

			dwPipeBytesReadTotal -= dwFileBytesRead;
			bRet = true;

			free(pvBuffer);
			Sleep(1000);
		}

		return bRet;
	}

	bool CRedirectedIOPipe::__Read(std::string& stBuffer)
	{
		if (!m_hOutReadPipe || m_hOutReadPipe == INVALID_HANDLE_VALUE)
		{
			CLogManager::Instance().Log(LL_ERR, "Output read pipe is not valid!");
			return false;
		}

		constexpr auto nBufSize = 2048;
		const auto pvReadBuffer = calloc(nBufSize, m_bUnicode ? sizeof(wchar_t) : sizeof(char));
		if (!pvReadBuffer)
		{
			CLogManager::Instance().Log(LL_ERR, "Read buffer allocation failed!");
			return false;
		}
		memset(pvReadBuffer, 0, nBufSize);

		DWORD dwPipeBytesRead = 0;
		if (!PeekNamedPipe(m_hOutReadPipe, nullptr, 0, nullptr, &dwPipeBytesRead, nullptr))
		{
			CLogManager::Instance().Log(LL_ERR, fmt::format("PeekNamedPipe failed with error: {0}", GetLastError()));
			free(pvReadBuffer);
			return false;
		}

		if (!dwPipeBytesRead)
		{
			CLogManager::Instance().Log(LL_ERR, "Have not any readable data in CMD pipe!");
			free(pvReadBuffer);
			return false;
		}

		CLogManager::Instance().Log(LL_SYS, fmt::format("{0} bytes is readable in pipe!", dwPipeBytesRead));

		while (dwPipeBytesRead)
		{
			const auto dwReadSize = (dwPipeBytesRead < nBufSize) ? dwPipeBytesRead : nBufSize;

			DWORD dwFileBytesRead = 0;
			if (!ReadFile(m_hOutReadPipe, pvReadBuffer, dwReadSize, &dwFileBytesRead, nullptr))
			{
				free(pvReadBuffer);
				CLogManager::Instance().Log(LL_ERR, fmt::format("ReadFile failed with read size: {0} error: {1}", dwFileBytesRead, GetLastError()));
				return false;
			}

			auto stBufferCopy = ""s;
			if (m_bUnicode)
			{
				const auto wstBufferCopy = std::wstring(reinterpret_cast<wchar_t*>(pvReadBuffer), dwFileBytesRead);
				stBufferCopy = CUtilites::Instance().ToAnsiString(wstBufferCopy);
			}
			else
			{
				stBufferCopy = std::string(reinterpret_cast<char*>(pvReadBuffer), dwFileBytesRead);
			}

			stBuffer += stBufferCopy;
			dwPipeBytesRead -= dwFileBytesRead;
		}

#ifdef _DEBUG
		CLogManager::Instance().Log(LL_SYS, fmt::format("Read succesfully completed! Buffer: {0} ({1})", stBuffer.c_str(), stBuffer.size()));
#endif
		free(pvReadBuffer);
		return __FixCommandOutput(stBuffer);
	}
	
	bool CRedirectedIOPipe::__Write(const std::string& stBuffer)
	{
		if (!m_hInWritePipe || m_hInWritePipe == INVALID_HANDLE_VALUE)
		{
			CLogManager::Instance().Log(LL_ERR, "Input write pipe is not valid!");
			return false;
		}

		SetLastError(0);

		DWORD dwWrited = 0;
		const auto bRet = WriteFile(m_hInWritePipe, stBuffer.c_str(), stBuffer.size(), &dwWrited, nullptr);

#ifdef _DEBUG
		const auto stLogBuffer = fmt::format(
			"WriteFile completed! Buffer: {0}({1}) Writed: {2} Completed: {3} Last error: {4}",
			stBuffer, stBuffer.size(), dwWrited, bRet, GetLastError()
		);
		CLogManager::Instance().Log(bRet ? LL_SYS : LL_ERR, stLogBuffer);
#endif

		return bRet;
	}
}
