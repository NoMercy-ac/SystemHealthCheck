#pragma once
#include "abstract_singleton.hpp"

namespace SystemHealthCheck
{
	struct SFileReadCtx
	{
		LPVOID lpBuffer{ nullptr };
		SIZE_T dwSize{ 0 };
	};

	class CUtilites : public CSingleton <CUtilites>
	{
	public:
		CUtilites();
		virtual ~CUtilites();

		std::string ToAnsiString(const std::wstring& wstBuffer);
		std::string GetErrorDetailsA(int nErrorCode);
		std::wstring GetErrorDetailsW(int nErrorCode);
		std::string GetSystemErrorReason(DWORD dwErrorCode);
		DWORD GetCurrentTimestamp();
		DWORD GetWindowsMajorVersion();
		bool IsSysWow64();
		bool ManageFsRedirection(bool bDisable, PVOID pCookie, PVOID* ppCookie);
		SFileReadCtx ReadFileContent(const std::wstring& wstFileName);
		bool IsContentNumber(const std::string& s);
		bool IsFileDigitalSigned(const std::wstring& wstFileName);
		bool EnablePrivilege(const std::string& stPrivilege);
		bool ProcessIsItAlive(DWORD dwProcessId);
		DWORD GetProcessIdFromProcessName(std::string stProcessName);
		bool HasSuspendedThread(DWORD dwProcessId);
		bool IsServiceIntegirtyCorrupted(const std::string& stServiceName);
		bool ChangeServiceStartType(const std::string& stServiceName, DWORD dwNewStatus);
		bool ServiceStart(const std::string& stServiceName);
		bool ServiceStop(const std::string& stServiceName);
		bool IsKnownProcessor();
		bool IsSafeModeEnabled();
		bool IsCompatibleModeEnabled(const std::string& stAppName);
		bool IsKernelDebuggerEnabled();
		bool IsSecureBootDisabled();
		bool IsTestSignEnabled();
		bool IsCustomKernelSignersAllowed();
	};
}

namespace WinAPI
{
	typedef struct _SYSTEM_KERNEL_DEBUGGER_INFORMATION
	{
		BOOLEAN KernelDebuggerEnabled;
		BOOLEAN KernelDebuggerNotPresent;
	} SYSTEM_KERNEL_DEBUGGER_INFORMATION, * PSYSTEM_KERNEL_DEBUGGER_INFORMATION;

	typedef struct _SYSTEM_BOOT_ENVIRONMENT_INFORMATION
	{
		GUID BootIdentifier;
		FIRMWARE_TYPE FirmwareType;
		union
		{
			ULONGLONG BootFlags;
			struct
			{
				ULONGLONG DbgMenuOsSelection : 1;
				ULONGLONG DbgHiberBoot : 1;
				ULONGLONG DbgSoftBoot : 1;
				ULONGLONG DbgMeasuredLaunch : 1;
				ULONGLONG DbgMeasuredLaunchCapable : 1;
				ULONGLONG DbgSystemHiveReplace : 1;
				ULONGLONG DbgMeasuredLaunchSmmProtections : 1;
			};
		};
	} SYSTEM_BOOT_ENVIRONMENT_INFORMATION, * PSYSTEM_BOOT_ENVIRONMENT_INFORMATION;

	typedef struct _SYSTEM_SECUREBOOT_INFORMATION
	{
		BOOLEAN SecureBootEnabled;
		BOOLEAN SecureBootCapable;
	} SYSTEM_SECUREBOOT_INFORMATION, * PSYSTEM_SECUREBOOT_INFORMATION;

	typedef struct _SYSTEM_CODEINTEGRITY_INFORMATION
	{
		ULONG Length;
		ULONG CodeIntegrityOptions;
	} SYSTEM_CODEINTEGRITY_INFORMATION, * PSYSTEM_CODEINTEGRITY_INFORMATION;
};
