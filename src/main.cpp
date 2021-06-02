#include "../include/pch.hpp"
#include "../include/log_manager.hpp"
#include "../include/redirected_io_pipe.hpp"
#include "../include/module_validator.hpp"
#include "../include/net_manager.hpp"
#include "../include/win_update_manager.hpp"
#include "../include/wmi_manager.hpp"
#include "../include/amsi_scanner.hpp"
#include "../include/utilities.hpp"
#include "../include/restore_point_helper.hpp"
using namespace SystemHealthCheck;

enum class EWorkType : uint8_t
{
	WORK_TYPE_NONE,
	WORK_TYPE_SYSCHECK,
	WORK_TYPE_REPAIR_SYSTEM,
	WORK_TYPE_ENABLE_PROCESS_MONITOR,
	WORK_TYPE_DISABLE_PROCESS_MONITOR
};

static auto gs_nWorkType = EWorkType::WORK_TYPE_NONE;

#ifdef _DEBUG
static auto gs_nNomercyVersion = 1337U;
#else
static auto gs_nNomercyVersion = 0U;
#endif

static void HealthCheckWorker()
{
	CLogManager::Instance().Log(LL_SYS, "System health checker started!");

	if (gs_nWorkType == EWorkType::WORK_TYPE_ENABLE_PROCESS_MONITOR || gs_nWorkType == EWorkType::WORK_TYPE_DISABLE_PROCESS_MONITOR)
	{
		if (!std::filesystem::exists("procmon.exe"))
		{
			CLogManager::Instance().Log(LL_ERR, "Process monitor component does not exist!");
			return;
		}

		auto stProcMonExecutable = ""s;
		if (gs_nWorkType == EWorkType::WORK_TYPE_ENABLE_PROCESS_MONITOR)
		{
			if (CUtilites::Instance().GetProcessIdFromProcessName("procmon.exe"))
			{
				CLogManager::Instance().Log(LL_ERR, "Process monitor is already running!");
				return;
			}

			stProcMonExecutable = "procmon.exe -accepteula -backingfile c:\\systemhealthcheck.pml -quiet";
		}
		else
		{
			if (!CUtilites::Instance().GetProcessIdFromProcessName("procmon.exe"))
			{
				CLogManager::Instance().Log(LL_ERR, "Process monitor is not running!");
				return;
			}

			stProcMonExecutable = "procmon.exe -accepteula -terminate -quiet";
		}

		// Initialize COM before calling ShellExecute().
		CoInitializeEx(NULL, COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE);

		// Execute process
		const auto iExecuteRet = (INT_PTR)ShellExecuteA(nullptr, "runas", stProcMonExecutable.c_str(), nullptr, nullptr, SW_HIDE);
		if (iExecuteRet <= 32) // If the function succeeds, it returns a value greater than 32.
		{
			CLogManager::Instance().Log(LL_ERR, fmt::format("ShellExecuteA failed with status: {0}", iExecuteRet));
			return;
		}

		CLogManager::Instance().Log(LL_SYS, "System health checker completed!");
		return;
	}

	// At the first, check network status
	if (!CNetworkManager::Instance().CheckInternetStatus())
	{
		CLogManager::Instance().Log(LL_ERR, "Internet status validation failed!");
		return;
	}
	if (!CNetworkManager::Instance().CheckNoMercyServerStatus())
	{
		CLogManager::Instance().Log(LL_ERR, "NoMercy server status validation failed!");
		return;
	}
	if (!CNetworkManager::Instance().CheckNoMercyVersion(gs_nNomercyVersion))
	{
		CLogManager::Instance().Log(LL_ERR, "NoMercy version validation failed!");
		return;
	}

	// Check system module integritys
	if (!CModuleValidator::Instance().ValidateSystemModules())
	{
		CLogManager::Instance().Log(LL_ERR, "System module validation failed!");
		return;
	}

	// Check CMD pipe functionality
	DWORD dwCompNameSize = 250;
	char szComputerName[250] = { 0 };
	if (!GetComputerNameA(szComputerName, &dwCompNameSize))
	{
		CLogManager::Instance().Log(LL_ERR, fmt::format("GetComputerNameA failed with error: {0}", GetLastError()));
		return;
	}

	auto stCmdBuffer = "whoami"s;
	if (!CRedirectedIOPipe::Instance().RunCommand(stCmdBuffer, false) || stCmdBuffer.empty() || stCmdBuffer.find("\\") == std::string::npos)
	{
		CLogManager::Instance().Log(LL_ERR, "CMD test communication failed!");
		return;
	}
	stCmdBuffer = stCmdBuffer.substr(0, stCmdBuffer.find("\\"));

	if (StrCmpICA(szComputerName, stCmdBuffer.c_str()))
	{
		CLogManager::Instance().Log(LL_ERR, fmt::format("Corrupted CMD output: '{0}' - '{1}'", stCmdBuffer, szComputerName));
		return;
	}
	
	// Check Windows updates
	if (CWinUpdateManager::Instance().HasAnyUpdate())
	{
		CLogManager::Instance().Log(LL_ERR, "Windows update check failed!");
		return;
	}
	
	// Check WMI service & process status
	if (!CWMIManager::Instance().CheckWMIStatus(gs_nWorkType == EWorkType::WORK_TYPE_REPAIR_SYSTEM))
	{
		CLogManager::Instance().Log(LL_ERR, "WMI status check failed!");
		return;
	}

	// Check installed security tools from WMI
	if (!CWMIManager::Instance().CheckHasSecurityTools())
	{
		CLogManager::Instance().Log(LL_ERR, "WMI query security tool check failed!");
		return;
	}

	// Utility checks
	if (!CUtilites::Instance().IsKnownProcessor())
	{
		CLogManager::Instance().Log(LL_ERR, "System working with unallowed processor!");
		return;
	}

	if (CUtilites::Instance().IsSafeModeEnabled())
	{
		CLogManager::Instance().Log(LL_ERR, "System working on safe boot mode!");
		return;
	}

	if (CUtilites::Instance().IsCompatibleModeEnabled("nomercy"))
	{
		CLogManager::Instance().Log(LL_ERR, "Compatible mode is not allowed for current process or any NoMercy component!");
		return;
	}

	if (CUtilites::Instance().IsKernelDebuggerEnabled())
	{
		CLogManager::Instance().Log(LL_ERR, "Kernel debugger detected!");
		return;
	}

	if (CUtilites::Instance().IsSecureBootDisabled())
	{
		CLogManager::Instance().Log(LL_ERR, "Secureboot mode is capable but not enabled!");
		return;
	}

	if (CUtilites::Instance().IsTestSignEnabled())
	{
		CLogManager::Instance().Log(LL_ERR, "Test signature mode is enabled!");
		return;
	}

	if (CUtilites::Instance().IsCustomKernelSignersAllowed())
	{
		CLogManager::Instance().Log(LL_ERR, "Custom kernel signers is allowed!");
		return;
	}

	// Run lightweight system scanner
	if (!CAMSIScanManager::Instance().ScanSystem())
	{
		CLogManager::Instance().Log(LL_ERR, "System scanning failed!");
		return;
	}

	// Run system repair commands
	if (gs_nWorkType == EWorkType::WORK_TYPE_REPAIR_SYSTEM)
	{
		// Flush DNS
		stCmdBuffer = "ipconfig /flushdns";
		if (!CRedirectedIOPipe::Instance().RunCommand(stCmdBuffer))
		{
			CLogManager::Instance().Log(LL_ERR, "Flush DNS command execute failed!");
			return;
		}

		// Run CHKDSK
		stCmdBuffer = "echo Y^R^N | chkdsk %SYSTEMDRIVE% /f /r";
		if (!CRedirectedIOPipe::Instance().RunCommand(stCmdBuffer))
		{
			CLogManager::Instance().Log(LL_ERR, "CHKDSK command execute failed!");
			return;
		}

		// Check phase with pseudo cache file
		constexpr auto c_szCacheFileName = "SystemHealthCheck.cache";
		const auto bIsSecondPhase = std::filesystem::exists(c_szCacheFileName);

		if (!bIsSecondPhase)
		{
			// Create cache file
			std::ofstream ofs(c_szCacheFileName);
			if (!ofs)
			{
				CLogManager::Instance().Log(LL_ERR, "Cache file create failed!");
				return;
			}
			ofs << "";
			ofs.close();
		}
		else
		{
			// Delete cache file
			std::filesystem::remove(c_szCacheFileName);
		}

		// Just re-launch CMD child process with unicode environment because SFC process stdout is UTF-16
		CRedirectedIOPipe::Instance().Release();
		CRedirectedIOPipe::Instance().Initialize(true);

		// Run SFC
		stCmdBuffer = "sfc /scannow";
		if (!CRedirectedIOPipe::Instance().RunCommand(stCmdBuffer))
		{
			CLogManager::Instance().Log(LL_ERR, "SFC command execute failed!");
			return;
		}

		// Go back to ansi
		CRedirectedIOPipe::Instance().Release();
		CRedirectedIOPipe::Instance().Initialize(false);

		// First phase
		if (!bIsSecondPhase)
		{
			stCmdBuffer = "DISM /Online /Cleanup-Image /ScanHealth";
			if (!CRedirectedIOPipe::Instance().RunCommand(stCmdBuffer))
			{
				CLogManager::Instance().Log(LL_ERR, "DISM command (1) execute failed!");
				return;
			}
			stCmdBuffer = "DISM /Online /Cleanup-Image /CheckHealth";
			if (!CRedirectedIOPipe::Instance().RunCommand(stCmdBuffer))
			{
				CLogManager::Instance().Log(LL_ERR, "DISM command (2) execute failed!");
				return;
			}
			stCmdBuffer = "DISM /Online /Cleanup-Image /RestoreHealth";
			if (!CRedirectedIOPipe::Instance().RunCommand(stCmdBuffer))
			{
				CLogManager::Instance().Log(LL_ERR, "DISM command (3) execute failed!");
				return;
			}

			CLogManager::Instance().Log(LL_WARN, "Please reboot your machine and re-launch this application for continue.");
		}
		else // Second phase
		{
			stCmdBuffer = "DISM /Online /Cleanup-Image /AnalyzeComponentStore";
			if (!CRedirectedIOPipe::Instance().RunCommand(stCmdBuffer))
			{
				CLogManager::Instance().Log(LL_ERR, "DISM command (4) execute failed!");
				return;
			}
			stCmdBuffer = "DISM /Online /Cleanup-Image /StartComponentCleanup";
			if (!CRedirectedIOPipe::Instance().RunCommand(stCmdBuffer))
			{
				CLogManager::Instance().Log(LL_ERR, "DISM command (5) execute failed!");
				return;
			}

			CLogManager::Instance().Log(LL_WARN, "System repair is completed!");
		}
	}

	CLogManager::Instance().Log(LL_SYS, "System health checker completed!");
}

bool LoadNoMercyVersionFromModule()
{
#ifdef _DEBUG
	constexpr auto szDebugPostfix = "_d";
#else
	constexpr auto szDebugPostfix = "";
#endif

	const auto stCoreModuleName = fmt::format("NoMercy_Module_x{0}{1}.dll", BUILD_ARCH, szDebugPostfix);
	if (std::filesystem::exists(stCoreModuleName))
	{
		const auto hNoMercyCore = LoadLibraryA(stCoreModuleName.c_str());
		if (!hNoMercyCore)
		{
			CLogManager::Instance().Log(LL_ERR, fmt::format("LoadLibraryA ({0}) failed with status: {1}", stCoreModuleName.c_str(), GetLastError()));
			return false;
		}

		using fnCoreVersionHandler = uint32_t(*)();
		const auto lpCoreVersionHandler = reinterpret_cast<fnCoreVersionHandler>(GetProcAddress(hNoMercyCore, "GetVersionNumber"));
		if (!lpCoreVersionHandler)
		{
			CLogManager::Instance().Log(LL_ERR, fmt::format("GetProcAddress (GetVersionNumber) failed with status: {0}", GetLastError()));
			return false;
		}

		gs_nNomercyVersion = lpCoreVersionHandler();
		return !!gs_nNomercyVersion;
	}
	else
	{
		CLogManager::Instance().Log(LL_ERR, fmt::format("Core module: {0} does not exist!", stCoreModuleName));

		const auto stLoaderModuleName = fmt::format("NoMercy_Loader_x{0}{1}.dll", BUILD_ARCH, szDebugPostfix);
		if (!std::filesystem::exists(stLoaderModuleName))
		{
			CLogManager::Instance().Log(LL_ERR, fmt::format("Loader module: {0} does not exist!", stLoaderModuleName));
			return false;
		}

		const auto hNoMercyLoader = LoadLibraryA(stLoaderModuleName.c_str());
		if (!hNoMercyLoader)
		{
			CLogManager::Instance().Log(LL_ERR, fmt::format("LoadLibraryA ({0}) failed with status: {1}", stLoaderModuleName.c_str(), GetLastError()));
			return false;
		}

		using fnLoaderVersionHandler = uint32_t(*)();
		const auto lpLoaderVersionHandler = reinterpret_cast<fnLoaderVersionHandler>(GetProcAddress(hNoMercyLoader, "NM_GetCoreVersion"));
		if (!lpLoaderVersionHandler)
		{
			CLogManager::Instance().Log(LL_ERR, fmt::format("GetProcAddress (GetVersionNumber) failed with status: {0}", GetLastError()));
			return false;
		}

		gs_nNomercyVersion = lpLoaderVersionHandler();
		return !!gs_nNomercyVersion;
	}

	return false;
}

bool ParseCommandline(int argc, char* argv[])
{
	cxxopts::Options options(
		argv[0],
		"Required parameter: [t/type]\n"
		"Check only: 1\n"
		"Check and repair system: 2\n"
		"Enable system monitor: 3\n"
		"Disable system monitor: 4\n"
	);

	options.add_options()
		("t,type", "Work type", cxxopts::value<std::uint8_t>())
		("v,version", "Current version value", cxxopts::value<std::uint32_t>())
		("h,help", "Print usage")
	;

	if (argc < 2)
	{
		std::cout << options.help() << std::endl;
		return false;
	}

	try
	{
		auto result = options.parse(argc, argv);
		if (!result.count("type") || result.count("help"))
		{
			std::cout << options.help() << std::endl;
			return false;
		}

		gs_nWorkType = static_cast<EWorkType>(result["type"].as<std::uint8_t>());

		if (result.count("version"))
			gs_nNomercyVersion = result["version"].as<std::uint32_t>();

		return true;
	}
	catch (const cxxopts::OptionException& ex)
	{
		const auto msg = fmt::format("commandline parse cxxopts exception: {}", ex.what());
		Logf(CUSTOM_LOG_FILENAME, "%s", msg.c_str());
		return false;
	}
	catch (const std::exception& ex)
	{
		const auto msg = fmt::format("commandline parse std exception: {}", ex.what());
		Logf(CUSTOM_LOG_FILENAME, "%s", msg.c_str());
		return false;
	}
	catch (...)
	{
		assert(0 && "commandline parse unhandled exception");
		return false;
	}
}

int main(int argc, char* argv[])
{
	Logf(CUSTOM_LOG_FILENAME, "SystemHealthCheck application started!\n");

#ifndef _DEBUG
	std::cout << "Press to any key for continue to health check & repair...";
	std::cin.get();
#endif

	// Initialize log instance
	static CLogManager s_kLogManagerInstance("SystemHealthCheck", CUSTOM_LOG_FILENAME); 
	if (!CLogManager::InstancePtr() || !CLogManager::Instance().IsInitialized())
	{
		Logf(CUSTOM_LOG_FILENAME, "Log manager initilization failed!\n");	
		return EXIT_FAILURE;		
	}

	// Check & parse commandline
	if (!ParseCommandline(argc, argv))
	{
		Logf(CUSTOM_LOG_FILENAME, "Commandline parse failed!\n");
		return EXIT_FAILURE;
	}

	// Check pre-defined version
	if (!gs_nNomercyVersion)
	{
		// Load nomercy version from module
		if (!LoadNoMercyVersionFromModule())
		{
			CLogManager::Instance().Log(LL_ERR, "Missing NoMercy components detected!");
			return EXIT_FAILURE;
		}
	}
	CLogManager::Instance().Log(LL_SYS, fmt::format("Current NoMercy version: {0}", gs_nNomercyVersion));

#ifndef _DEBUG
	// Create system restore point
	if (gs_nWorkType == EWorkType::WORK_TYPE_REPAIR_SYSTEM && !CreateRestorePoint())
	{
		CLogManager::Instance().Log(LL_ERR, "System restore point create failed!");
		return EXIT_FAILURE;
	}
#endif

	// Create CMD pipe parameter
	wchar_t wszSysPath[MAX_PATH * 2] = { L'\0' };
	if (!GetSystemDirectoryW(wszSysPath, MAX_PATH))
	{
		CLogManager::Instance().Log(LL_ERR, fmt::format("GetSystemDirectoryW failed with error: {0}", GetLastError()));
		return EXIT_FAILURE;
	}

	const auto spPipeCtx = std::make_shared<SRedirectedIOPipeCtx>(L"", fmt::format(L"{0}\\cmd.exe", wszSysPath), nullptr);

	// Create worker instances
	static CRedirectedIOPipe s_kIOPipe(spPipeCtx);
	static CModuleValidator s_kModuleValidator;
	static CNetworkManager s_kNetworkManager;
	static CWinUpdateManager s_kWinUpdateManager;
	static CWMIManager s_kWMIManager;
	static CAMSIScanManager s_kAMSIScanManager;
	static CUtilites s_kUtilities;
	CLogManager::Instance().Log(LL_SYS, "Worker components are declared!");

	// Initialize worker instances
	if (!CRedirectedIOPipe::InstancePtr() || !CRedirectedIOPipe::Instance().Initialize())
	{
		CLogManager::Instance().Log(LL_ERR, "CMD Pipe create failed!");	
		return EXIT_FAILURE;
	}

	if (!CModuleValidator::InstancePtr() || !CModuleValidator::Instance().Initialize())
	{
		CLogManager::Instance().Log(LL_ERR, "Module validator initilization failed!");
		return EXIT_FAILURE;
	}

	if (!CNetworkManager::InstancePtr() || !CNetworkManager::Instance().Initialize())
	{
		CLogManager::Instance().Log(LL_ERR, "Network manager initilization failed!");
		return EXIT_FAILURE;
	}

	if (!CWinUpdateManager::InstancePtr() || !CWinUpdateManager::Instance().Initialize())
	{
		CLogManager::Instance().Log(LL_ERR, "Windows update manager initilization failed!");
		return EXIT_FAILURE;
	}

	if (!CWMIManager::InstancePtr() || !CWMIManager::Instance().Initialize())
	{
		CLogManager::Instance().Log(LL_ERR, "WMI manager initilization failed!");
		return EXIT_FAILURE;
	}

	if (!CAMSIScanManager::InstancePtr() || !CAMSIScanManager::Instance().Initialize())
	{
		CLogManager::Instance().Log(LL_ERR, "AMSI scan manager initilization failed!");
		return EXIT_FAILURE;
	}

	if (!CUtilites::InstancePtr())
	{
		CLogManager::Instance().Log(LL_ERR, "Utility function class is not declared!");
		return EXIT_FAILURE;
	}
	CLogManager::Instance().Log(LL_SYS, "Worker components are initialized!");

	// Start worker
	HealthCheckWorker();

	// Release instances
	CAMSIScanManager::Instance().Release();
	CWMIManager::Instance().Release();
	CWinUpdateManager::Instance().Release();
	CNetworkManager::Instance().Release();
	CModuleValidator::Instance().Release();
	CRedirectedIOPipe::Instance().Release();

	// Finish
	CLogManager::Instance().Log(LL_SYS, "SystemHealthCheck application completed!");
#ifdef _DEBUG
	std::cin.get();
#endif
	return EXIT_SUCCESS;
}
