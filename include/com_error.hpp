#pragma once

namespace SystemHealthCheck
{
	inline const auto ComErrorMessage(HRESULT hr)
	{
		_com_error err(hr);
		LPCTSTR errMsg = err.ErrorMessage();
		return errMsg;
	}
	inline const auto ComStrToStdStr(BSTR bszName)
	{
#pragma warning(push) 
#pragma warning(disable: 4242 4244)
		std::wstring wszName(bszName, SysStringLen(bszName));
#pragma warning(push) 
		return wszName;
	}

	class ComStr
	{
	public:
		ComStr(const std::string& in) : m_com_str(nullptr)
		{
			Initialize(std::wstring(in.begin(), in.end()));
		}
		ComStr(const std::wstring& in) : m_com_str(nullptr)
		{
			Initialize(in);
		}
		~ComStr()
		{
			if (m_com_str) SysFreeString(m_com_str);
		}

		operator BSTR ()
		{
			return m_com_str;
		}

	protected:
		void Initialize(const std::wstring& in)
		{
			if (!in.empty()) m_com_str = SysAllocString(in.c_str());
		}

	private:
		BSTR m_com_str;
	};
};
