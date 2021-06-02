#pragma once
#include "abstract_singleton.hpp"
#include "utilities.hpp"

namespace SystemHealthCheck
{
	struct SAmsiScanResult
	{
		HRESULT hrRiskLevel{ 0 };
		bool bIsMalware{ false };
	};

	class CAMSIScanManager : public CSingleton <CAMSIScanManager>
	{
	public:
		CAMSIScanManager();
		virtual ~CAMSIScanManager();

		bool Initialize();
		void Release();

		bool ScanSystem();
		bool IsMaliciousFile(const std::wstring& wstScanFile);

	protected:
		std::shared_ptr <SAmsiScanResult> __ScanFile(const std::wstring& wstFileName, const std::shared_ptr <SFileReadCtx>& spFileCtx);
		bool __GetFileContext(const std::wstring& wstFileName, std::shared_ptr <SFileReadCtx>& spFileCtx);
		std::wstring __GetResultDescription(HRESULT hrScore);

	private:
		bool m_bInitialized;
		HAMSICONTEXT m_pkRefAmsiContext;
		HAMSISESSION m_pkAmsiSession;
		std::vector <std::wstring> m_vScannedFiles;
	};
}
