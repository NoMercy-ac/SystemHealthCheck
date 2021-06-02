#pragma once

class CFirewallHelper
{
    using TEnumRules = std::function<bool(INetFwRule* FwRule, void* pvUserContext)>;

public:
    virtual ~CFirewallHelper()
    {
        __Clear();
    }

    CFirewallHelper(const CFirewallHelper&) = delete;
    CFirewallHelper(CFirewallHelper&&) noexcept = delete;
    CFirewallHelper& operator=(const CFirewallHelper&) = delete;
    CFirewallHelper& operator=(CFirewallHelper&&) noexcept = delete;

public:
    CFirewallHelper()
    {
        auto hr = CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE);
        if (hr != RPC_E_CHANGED_MODE && FAILED(hr))
        {
            std::cout << "CoInitializeEx failed! Error code: " << std::hex << hr << std::endl;
            throw hr;
        }

        try
        {
            if (FAILED(hr = CoCreateInstance(__uuidof(NetFwMgr), nullptr, CLSCTX_INPROC_SERVER, __uuidof(INetFwMgr), (void**)&m_fwMgr)))
            {
                std::cout << "CoCreateInstance(m_fwMgr) failed! Error code: " << std::hex << hr << std::endl;
                throw hr;
            }

            if (FAILED(hr = CoCreateInstance(__uuidof(NetFwPolicy2), nullptr, CLSCTX_INPROC_SERVER, __uuidof(INetFwPolicy2), (void**)&m_fwPolicy2)))
            {
                std::cout << "CoCreateInstance(m_fwPolicy2) failed! Error code: " << std::hex << hr << std::endl;
                throw hr;
            }

            if (FAILED(hr = m_fwMgr->get_LocalPolicy(&m_fwPolicy)))
            {
                std::cout << "get_LocalPolicy failed! Error code: " << std::hex << hr << std::endl;
                throw hr;
            }

            if (FAILED(hr = m_fwPolicy->get_CurrentProfile(&m_fwProfile)))
            {
                std::cout << "get_CurrentProfile failed! Error code: " << std::hex << hr << std::endl;
                throw hr;
            }
        }
        catch (const HRESULT& hr)
        {
            std::cout << "Exception handled: " << std::hex << hr << " Error: " << __GetComErrorDetails(hr) << std::endl;

            __Clear();
            throw hr;
        }
    }

    HRESULT IsFirewallEnabled(bool& pbEnabled)
    {
        auto hr = HRESULT{ S_OK };
        auto fwEnabled = VARIANT_BOOL{ VARIANT_FALSE };

        pbEnabled = false;
        try
        {
            if (FAILED(hr = m_fwProfile->get_FirewallEnabled(&fwEnabled)))
            {
                std::cout << "get_FirewallEnabled failed! Error code: " << std::hex << hr << std::endl;
                throw hr;
            }

            if (fwEnabled == VARIANT_TRUE)
                pbEnabled = true;
        }
        catch (const HRESULT& hr)
        {
            UNREFERENCED_PARAMETER(hr);
        }
        return hr;
    }

    HRESULT ManageFirewallState(bool bEnable)
    {
        auto hr = HRESULT{ S_OK };
        auto fwOn = false;

        if (FAILED(hr = IsFirewallEnabled(fwOn)))
        {
            std::cout << "IsFirewallEnabled failed! Error code: " << std::hex << hr << std::endl;
            return hr;
        }

        try
        {
            if (!fwOn && bEnable)
            {
                if (FAILED(hr = m_fwProfile->put_FirewallEnabled(VARIANT_TRUE)))
                {
                    std::cout << "put_FirewallEnabled failed! Error code: " << std::hex << hr << std::endl;
                    throw hr;
                }

                std::cout << "The firewall is now on." << std::endl;
            }
            else if (fwOn && !bEnable)
            {
                if (FAILED(hr = m_fwProfile->put_FirewallEnabled(VARIANT_FALSE)))
                {
                    std::cout << "put_FirewallEnabled failed! Error code: " << std::hex << hr << std::endl;
                    throw hr;
                }

                std::cout << "The firewall is now off." << std::endl;
            }
        }
        catch (const HRESULT& hr)
        {
            std::cout << "Exception handled: " << std::hex << hr << " Error: " << __GetComErrorDetails(hr) << std::endl;
            throw hr;
        }

        return hr;
    }

    void EnumerateRules(TEnumRules pfnEnumRulesCb, LPVOID pvUserContext)
    {
        auto hr = HRESULT{ S_OK };

        auto cFetched = 0UL;
        auto var = CComVariant{};

        IUnknown* pEnumerator{};
        IEnumVARIANT* pVariant = nullptr;

        INetFwRules* pFwRules = nullptr;
        INetFwRule* pFwRule = nullptr;

        auto fwRuleCount = 0L;

        try
        {
            if (FAILED(hr = m_fwPolicy2->get_Rules(&pFwRules)))
            {
                std::cout << "get_Rules failed! Error code: " << std::hex << hr << std::endl;
                throw hr;
            }

            if (FAILED(hr = pFwRules->get_Count(&fwRuleCount)))
            {
                std::cout << "get_Count failed! Error code: " << std::hex << hr << std::endl;
                throw hr;
            }

            pFwRules->get__NewEnum(&pEnumerator);

            if (pEnumerator)
                hr = pEnumerator->QueryInterface(__uuidof(IEnumVARIANT), (void**)&pVariant);

            while (SUCCEEDED(hr) && hr != S_FALSE)
            {
                var.Clear();
                hr = pVariant->Next(1, &var, &cFetched);

                if (S_FALSE != hr)
                {
                    if (SUCCEEDED(hr))
                    {
                        hr = var.ChangeType(VT_DISPATCH);
                    }
                    if (SUCCEEDED(hr))
                    {
                        hr = (V_DISPATCH(&var))->QueryInterface(__uuidof(INetFwRule), reinterpret_cast<void**>(&pFwRule));
                    }

                    if (SUCCEEDED(hr))
                    {
                        if (!pfnEnumRulesCb(pFwRule, pvUserContext))
                            break;
                    }
                }
            }
        }
        catch (const HRESULT& hr)
        {
            std::cout << "Exception handled: " << std::hex << hr << " Error: " << __GetComErrorDetails(hr) << std::endl;
            throw hr;
        }
    }

    HRESULT AddRule(const std::wstring& c_wstRuleName, const std::wstring& c_wstRuleDesc, const std::wstring& c_wstGroupName, const std::wstring& c_wstAppPath, INetFwRule** pRulePtr)
    {
        auto hr = HRESULT{ S_OK };

        INetFwRules* pFwRules = nullptr;
        INetFwRule* pFwRule = nullptr;

        auto bstrRuleName = SysAllocString(c_wstRuleName.c_str());
        auto bstrRuleDescription = SysAllocString(c_wstRuleDesc.c_str());
        auto bstrRuleGroup = SysAllocString(c_wstGroupName.c_str());
        auto bstrRuleApplication = SysAllocString(c_wstAppPath.c_str());

        try
        {
            if (FAILED(hr = m_fwPolicy2->get_Rules(&pFwRules)))
            {
                std::cout << "get_Rules failed! Error code: " << std::hex << hr << std::endl;
                throw hr;
            }

            if (FAILED(hr = CoCreateInstance(__uuidof(NetFwRule), nullptr, CLSCTX_INPROC_SERVER, __uuidof(INetFwRule), (void**)&pFwRule)))
            {
                std::cout << "CoCreateInstance(pFwRule) failed! Error code: " << std::hex << hr << std::endl;
                throw hr;
            }

            pFwRule->put_Name(bstrRuleName);
            pFwRule->put_Description(bstrRuleDescription);
            pFwRule->put_ApplicationName(bstrRuleApplication);
            pFwRule->put_Protocol(NET_FW_IP_PROTOCOL_TCP);
            pFwRule->put_Direction(NET_FW_RULE_DIR_MAX); // Inbound & Outbound
            pFwRule->put_Grouping(bstrRuleGroup);
            pFwRule->put_Profiles(NET_FW_PROFILE2_ALL); // Local & Private & Public
            pFwRule->put_Action(NET_FW_ACTION_BLOCK);
            pFwRule->put_Enabled(VARIANT_TRUE);

            if (FAILED(hr = pFwRules->Add(pFwRule)))
            {
                std::cout << "Rule Add failed! Error code: " << std::hex << hr << std::endl;
                throw hr;
            }
        }
        catch (const HRESULT& hr)
        {
            std::cout << "Exception handled: " << std::hex << hr << " Error: " << __GetComErrorDetails(hr) << std::endl;
            throw hr;
        }

        SysFreeString(bstrRuleName);
        SysFreeString(bstrRuleDescription);
        SysFreeString(bstrRuleGroup);
        SysFreeString(bstrRuleApplication);

        if (pFwRules)
        {
            pFwRules->Release();
            pFwRules = nullptr;
        }

        *pRulePtr = pFwRule;
        return hr;
    }

    HRESULT RemoveRule(const std::wstring& c_wstRuleName)
    {
        auto hr = HRESULT{ S_OK };
        INetFwRules* pFwRules = nullptr;

        auto bstrRuleName = SysAllocString(c_wstRuleName.c_str());

        try
        {
            if (FAILED(hr = m_fwPolicy2->get_Rules(&pFwRules)))
            {
                std::cout << "get_Rules failed! Error code: " << std::hex << hr << std::endl;
                throw hr;
            }

            if (FAILED(hr = pFwRules->Remove(bstrRuleName)))
            {
                std::cout << "Rule Remove failed! Error code: " << std::hex << hr << std::endl;
                throw hr;
            }
        }
        catch (const HRESULT& hr)
        {
            std::cout << "Exception handled: " << std::hex << hr << " Error: " << __GetComErrorDetails(hr) << std::endl;
            throw hr;
        }

        SysFreeString(bstrRuleName);

        if (pFwRules)
        {
            pFwRules->Release();
            pFwRules = nullptr;
        }

        return hr;
    }

    bool IsEnabledRule(INetFwRule* pFwRule)
    {
        assert(pFwRule);

        auto hr = HRESULT{ S_OK };
        auto vbEnabled = VARIANT_BOOL{ VARIANT_FALSE };

        try
        {
            hr = pFwRule->get_Enabled(&vbEnabled);
            if (FAILED(hr))
            {
                std::cout << "get_Enabled failed! Error code: " << std::hex << hr << std::endl;
                throw hr;
            }
        }
        catch (const HRESULT& hr)
        {
            std::cout << "Exception handled: " << std::hex << hr << " Error: " << __GetComErrorDetails(hr) << std::endl;
            throw hr;
        }

        return __VariantBoolToBool(vbEnabled);
    }

    HRESULT EnableRule(INetFwRule* pFwRule, bool bEnable)
    {
        assert(pFwRule);

        auto hr = HRESULT{ S_OK };
        auto bEnabled = IsEnabledRule(pFwRule);

        try
        {
            if (bEnable && bEnabled)
            {
                std::cout << "Rule already enabled!" << std::endl;
                return S_FALSE;
            }
            else if (!bEnable && !bEnabled)
            {
                std::cout << "Rule already disabled!" << std::endl;
                return S_FALSE;
            }

            if (FAILED(hr = pFwRule->put_Enabled(__BoolToVariantBool(bEnabled))))
            {
                std::cout << "put_Enabled failed! Error code: " << std::hex << hr << std::endl;
                throw hr;
            }
        }
        catch (const HRESULT& hr)
        {
            std::cout << "Exception handled: " << std::hex << hr << " Error: " << __GetComErrorDetails(hr) << std::endl;
            throw hr;
        }

        return hr;
    }

protected:
    void __Clear()
    {
        if (m_fwProfile)
        {
            m_fwProfile->Release();
            m_fwProfile = nullptr;
        }
        if (m_fwPolicy)
        {
            m_fwPolicy->Release();
            m_fwPolicy = nullptr;
        }
        if (m_fwPolicy2)
        {
            m_fwPolicy2->Release();
            m_fwPolicy2 = nullptr;
        }
        if (m_fwMgr)
        {
            m_fwMgr->Release();
            m_fwMgr = nullptr;
        }

        CoUninitialize();
    }

    VARIANT_BOOL __BoolToVariantBool(bool bBool)
    {
        return bBool ? VARIANT_TRUE : VARIANT_FALSE;
    }
    bool __VariantBoolToBool(VARIANT_BOOL vbBool)
    {
        return (vbBool == VARIANT_TRUE);
    }

    const char* __GetComErrorDetails(HRESULT hr)
    {
        const _com_error err(hr);
        return err.ErrorMessage();
    }

private:
    INetFwMgr* m_fwMgr;

    INetFwProfile* m_fwProfile;
    INetFwPolicy* m_fwPolicy;
    INetFwPolicy2* m_fwPolicy2;
};
