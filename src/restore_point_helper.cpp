#include "../include/pch.hpp"
#include "../include/restore_point_helper.hpp"
#include "../include/log_manager.hpp"

namespace SystemHealthCheck
{
	BOOL InitializeCOMSecurity()
	{
		BOOL fRet = FALSE;
		ACL* pAcl = NULL;

		do
		{
			// Initialize the security descriptor.
			SECURITY_DESCRIPTOR securityDesc = { 0 };
			fRet = InitializeSecurityDescriptor(&securityDesc, SECURITY_DESCRIPTOR_REVISION);
			if (!fRet)
			{
				CLogManager::Instance().Log(LL_ERR, fmt::format("InitializeSecurityDescriptor failed with error: {0}", GetLastError()));
				break;
			}

			// Create an administrator group security identifier (SID).
			ULONGLONG  rgSidBA[(SECURITY_MAX_SID_SIZE + sizeof(ULONGLONG) - 1) / sizeof(ULONGLONG)] = { 0 };
			DWORD cbSid = sizeof(rgSidBA);
			fRet = CreateWellKnownSid(WinBuiltinAdministratorsSid, NULL, rgSidBA, &cbSid);
			if (!fRet)
			{
				CLogManager::Instance().Log(LL_ERR, fmt::format("CreateWellKnownSid(WinBuiltinAdministratorsSid) failed with error: {0}", GetLastError()));
				break;
			}

			// Create a local service security identifier (SID).
			ULONGLONG  rgSidLS[(SECURITY_MAX_SID_SIZE + sizeof(ULONGLONG) - 1) / sizeof(ULONGLONG)] = { 0 };
			cbSid = sizeof(rgSidLS);
			fRet = CreateWellKnownSid(WinLocalServiceSid, NULL, rgSidLS, &cbSid);
			if (!fRet)
			{
				CLogManager::Instance().Log(LL_ERR, fmt::format("CreateWellKnownSid(WinLocalServiceSid) failed with error: {0}", GetLastError()));
				break;
			}

			// Create a network service security identifier (SID).
			ULONGLONG  rgSidNS[(SECURITY_MAX_SID_SIZE + sizeof(ULONGLONG) - 1) / sizeof(ULONGLONG)] = { 0 };
			cbSid = sizeof(rgSidNS);
			fRet = CreateWellKnownSid(WinNetworkServiceSid, NULL, rgSidNS, &cbSid);
			if (!fRet)
			{
				CLogManager::Instance().Log(LL_ERR, fmt::format("CreateWellKnownSid(WinNetworkServiceSid) failed with error: {0}", GetLastError()));
				break;
			}

			// Create a personal account security identifier (SID).
			ULONGLONG  rgSidPS[(SECURITY_MAX_SID_SIZE + sizeof(ULONGLONG) - 1) / sizeof(ULONGLONG)] = { 0 };
			cbSid = sizeof(rgSidPS);
			fRet = CreateWellKnownSid(WinSelfSid, NULL, rgSidPS, &cbSid);
			if (!fRet)
			{
				CLogManager::Instance().Log(LL_ERR, fmt::format("CreateWellKnownSid(WinSelfSid) failed with error: {0}", GetLastError()));
				break;
			}

			// Create a local service security identifier (SID).
			ULONGLONG  rgSidSY[(SECURITY_MAX_SID_SIZE + sizeof(ULONGLONG) - 1) / sizeof(ULONGLONG)] = { 0 };
			cbSid = sizeof(rgSidSY);
			fRet = CreateWellKnownSid(WinLocalSystemSid, NULL, rgSidSY, &cbSid);
			if (!fRet)
			{
				CLogManager::Instance().Log(LL_ERR, fmt::format("CreateWellKnownSid(WinLocalSystemSid) failed with error: {0}", GetLastError()));
				break;
			}

			// Setup the access control entries (ACE) for COM. You may need to modify 
			// the access permissions for your application. COM_RIGHTS_EXECUTE and
			// COM_RIGHTS_EXECUTE_LOCAL are the minimum access rights required.

			EXPLICIT_ACCESS ea[5] = { 0 };
			ea[0].grfAccessPermissions = COM_RIGHTS_EXECUTE | COM_RIGHTS_EXECUTE_LOCAL;
			ea[0].grfAccessMode = SET_ACCESS;
			ea[0].grfInheritance = NO_INHERITANCE;
			ea[0].Trustee.pMultipleTrustee = NULL;
			ea[0].Trustee.MultipleTrusteeOperation = NO_MULTIPLE_TRUSTEE;
			ea[0].Trustee.TrusteeForm = TRUSTEE_IS_SID;
			ea[0].Trustee.TrusteeType = TRUSTEE_IS_GROUP;
			ea[0].Trustee.ptstrName = (LPTSTR)rgSidBA;

			ea[1].grfAccessPermissions = COM_RIGHTS_EXECUTE | COM_RIGHTS_EXECUTE_LOCAL;
			ea[1].grfAccessMode = SET_ACCESS;
			ea[1].grfInheritance = NO_INHERITANCE;
			ea[1].Trustee.pMultipleTrustee = NULL;
			ea[1].Trustee.MultipleTrusteeOperation = NO_MULTIPLE_TRUSTEE;
			ea[1].Trustee.TrusteeForm = TRUSTEE_IS_SID;
			ea[1].Trustee.TrusteeType = TRUSTEE_IS_GROUP;
			ea[1].Trustee.ptstrName = (LPTSTR)rgSidLS;

			ea[2].grfAccessPermissions = COM_RIGHTS_EXECUTE | COM_RIGHTS_EXECUTE_LOCAL;
			ea[2].grfAccessMode = SET_ACCESS;
			ea[2].grfInheritance = NO_INHERITANCE;
			ea[2].Trustee.pMultipleTrustee = NULL;
			ea[2].Trustee.MultipleTrusteeOperation = NO_MULTIPLE_TRUSTEE;
			ea[2].Trustee.TrusteeForm = TRUSTEE_IS_SID;
			ea[2].Trustee.TrusteeType = TRUSTEE_IS_GROUP;
			ea[2].Trustee.ptstrName = (LPTSTR)rgSidNS;

			ea[3].grfAccessPermissions = COM_RIGHTS_EXECUTE | COM_RIGHTS_EXECUTE_LOCAL;
			ea[3].grfAccessMode = SET_ACCESS;
			ea[3].grfInheritance = NO_INHERITANCE;
			ea[3].Trustee.pMultipleTrustee = NULL;
			ea[3].Trustee.MultipleTrusteeOperation = NO_MULTIPLE_TRUSTEE;
			ea[3].Trustee.TrusteeForm = TRUSTEE_IS_SID;
			ea[3].Trustee.TrusteeType = TRUSTEE_IS_GROUP;
			ea[3].Trustee.ptstrName = (LPTSTR)rgSidPS;

			ea[4].grfAccessPermissions = COM_RIGHTS_EXECUTE | COM_RIGHTS_EXECUTE_LOCAL;
			ea[4].grfAccessMode = SET_ACCESS;
			ea[4].grfInheritance = NO_INHERITANCE;
			ea[4].Trustee.pMultipleTrustee = NULL;
			ea[4].Trustee.MultipleTrusteeOperation = NO_MULTIPLE_TRUSTEE;
			ea[4].Trustee.TrusteeForm = TRUSTEE_IS_SID;
			ea[4].Trustee.TrusteeType = TRUSTEE_IS_GROUP;
			ea[4].Trustee.ptstrName = (LPTSTR)rgSidSY;

			// Create an access control list (ACL) using this ACE list.
			const auto dwRet = SetEntriesInAclA(ARRAYSIZE(ea), ea, NULL, &pAcl);
			if (dwRet != ERROR_SUCCESS || pAcl == NULL)
			{
				CLogManager::Instance().Log(LL_ERR, fmt::format("SetEntriesInAclA failed with status: {0} error: {1}", dwRet, GetLastError()));
				fRet = FALSE;
				break;
			}

			// Set the security descriptor owner to Administrators.
			fRet = SetSecurityDescriptorOwner(&securityDesc, rgSidBA, FALSE);
			if (!fRet)
			{
				CLogManager::Instance().Log(LL_ERR, fmt::format("SetSecurityDescriptorOwner failed with error: {0}", GetLastError()));
				break;
			}

			// Set the security descriptor group to Administrators.
			fRet = SetSecurityDescriptorGroup(&securityDesc, rgSidBA, FALSE);
			if (!fRet)
			{
				CLogManager::Instance().Log(LL_ERR, fmt::format("SetSecurityDescriptorGroup failed with error: {0}", GetLastError()));
				break;
			}

			// Set the discretionary access control list (DACL) to the ACL.
			fRet = SetSecurityDescriptorDacl(&securityDesc, TRUE, pAcl, FALSE);
			if (!fRet)
			{
				CLogManager::Instance().Log(LL_ERR, fmt::format("SetSecurityDescriptorDacl failed with error: {0}", GetLastError()));
				break;
			}

			// Initialize COM. You may need to modify the parameters of
			// CoInitializeSecurity() for your application. Note that an
			// explicit security descriptor is being passed down.
			const auto hrRet = CoInitializeSecurity(&securityDesc,
				-1,
				NULL,
				NULL,
				RPC_C_AUTHN_LEVEL_PKT_PRIVACY,
				RPC_C_IMP_LEVEL_IDENTIFY,
				NULL,
				EOAC_DISABLE_AAA | EOAC_NO_CUSTOM_MARSHAL,
				NULL
			);
			if (FAILED(hrRet))
			{
				CLogManager::Instance().Log(LL_ERR, fmt::format("CoInitializeSecurity failed with status: {0}", fmt::ptr(reinterpret_cast<void*>(hrRet))));
				fRet = FALSE;
				break;
			}

			fRet = TRUE;
		} while (FALSE);

		if (pAcl)
			LocalFree(pAcl);

		return fRet;
	}

	bool CreateRestorePoint()
	{
		const auto hr = CoInitializeEx(NULL, COINIT_MULTITHREADED);
		if (FAILED(hr))
		{
			CLogManager::Instance().Log(LL_ERR, fmt::format("CoInitializeEx failed with status: {0}", fmt::ptr(reinterpret_cast<void*>(hr))));
			return false;
		}

		// Initialize COM security to enable NetworkService,
		// LocalService and System to make callbacks to the process 
		// calling  System Restore. This is required for any process
		// that calls SRSetRestorePoint.
		auto bRet = InitializeCOMSecurity();
		if (!bRet)
		{
			CLogManager::Instance().Log(LL_ERR, fmt::format("InitializeCOMSecurity failed. Last error: {0}", GetLastError()));
			return false;
		}

		// Initialize the RESTOREPOINTINFO structure
		RESTOREPOINTINFOW RestorePtInfo;
		RestorePtInfo.dwEventType = BEGIN_SYSTEM_CHANGE;
		RestorePtInfo.dwRestorePtType = MODIFY_SETTINGS;
		RestorePtInfo.llSequenceNumber = 0; // RestPtInfo.llSequenceNumber must be 0 when creating a restore point.
		StringCbCopyW(RestorePtInfo.szDescription, sizeof(RestorePtInfo.szDescription), L"SystemHealthCheck");

		STATEMGRSTATUS SMgrStatus;
		bRet = SRSetRestorePointW(&RestorePtInfo, &SMgrStatus);
		if (!bRet)
		{
			const auto dwErr = SMgrStatus.nStatus;
			if (dwErr == ERROR_SERVICE_DISABLED)
			{
				CLogManager::Instance().Log(LL_ERR, "System restore is turned off!");
				return false;
			}

			CLogManager::Instance().Log(LL_ERR, fmt::format("System restore point create failed with error: {0}", dwErr));
			return false;
		}

		// The application performs some installation operations here.

		// It is not necessary to call SrSetRestorePoint to indicate that the 
		// installation is complete except in the case of ending a nested 
		// restore point. Every BEGIN_NESTED_SYSTEM_CHANGE must have a 
		// corresponding END_NESTED_SYSTEM_CHANGE or the application cannot 
		// create new restore points.

		// Update the RESTOREPOINTINFO structure to notify the 
		// system that the operation is finished.
		RestorePtInfo.dwEventType = END_SYSTEM_CHANGE;

		// End the system change by using the sequence number 
		// received from the first call to SRSetRestorePoint.
		RestorePtInfo.llSequenceNumber = SMgrStatus.llSequenceNumber;

		// Notify the system that the operation is done and that this
		// is the end of the restore point.
		bRet = SRSetRestorePointW(&RestorePtInfo, &SMgrStatus);
		if (!bRet)
		{
			CLogManager::Instance().Log(LL_ERR, fmt::format("System restore point create complete failed with error: {0} status: {1}", GetLastError(), SMgrStatus.nStatus));
			return false;
		}

		CLogManager::Instance().Log(LL_SYS, fmt::format("Restore point created; number={0} status={1}", SMgrStatus.llSequenceNumber, SMgrStatus.nStatus));
		return true;
	}
};
