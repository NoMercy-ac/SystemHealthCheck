#pragma once
#include "abstract_singleton.hpp"
#include "basic_log.hpp"
#include <spdlog/spdlog.h>
#include <spdlog/sinks/msvc_sink.h>
#include <spdlog/sinks/basic_file_sink.h>
#include <spdlog/sinks/stdout_sinks.h>
#include <spdlog/sinks/stdout_color_sinks.h>

namespace SystemHealthCheck
{
	static constexpr auto CUSTOM_LOG_FILENAME = "SystemHealthCheck.log";
	static constexpr auto CUSTOM_LOG_ERROR_FILENAME = "SystemHealthCheckError.log";
	static constexpr auto CUSTOM_LOG_HISTORY_FILENAME = "SystemHealthCheckCMD.log";

	enum ELogLevels
	{
		LL_SYS,
		LL_ERR,
		LL_CRI,
		LL_WARN,
		LL_DEV,
		LL_TRACE
	};

	class CLogManager : public CSingleton <CLogManager>
	{
	public:
		CLogManager() = default;
		CLogManager(const std::string& stLoggerName, const std::string& stFileName);

		void Log(int32_t nLevel, const std::string& stBuffer);
		void Log(int32_t nLevel, const std::wstring& wstBuffer);

		auto IsInitialized() const { return !!m_pkLoggerImpl.get(); };
		
	private:
		mutable std::recursive_mutex		m_pkMtMutex;

		std::shared_ptr <spdlog::logger>	m_pkLoggerImpl;
		std::string							m_stLoggerName;
		std::string							m_stFileName;
	};
}
