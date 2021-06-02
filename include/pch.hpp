#include <Windows.h>
#include <Windowsx.h>
#include <TlHelp32.h>
#include <Psapi.h>
#include <VersionHelpers.h>
#include <amsi.h>
#include <Softpub.h>
#include <WinTrust.h>
#include <netfw.h>
#include <wuapi.h>
#include <wuerror.h>
#include <WbemCli.h>
#include <WbemIdl.h>
#include <AclAPI.h>
#include <srrestoreptapi.h>
#include <comdef.h>
#include <comutil.h>
#include <ShlObj.h>
#include <Shlwapi.h>
#include <WinInet.h>
#include <atlcomcli.h>
#include <strsafe.h>
#include <iostream>
#include <fstream>
#include <unordered_map>
#include <memory>
#include <algorithm>
#include <functional>
#include <filesystem>
#include <csignal>
#include <thread>
#include <atomic>
#include <ctime>
#include <cstring>
#include <cassert>

#include <cxxopts.hpp>
#include <fmt/format.h>
using namespace std::string_literals;

#ifndef SAFE_RELEASE
    #define SAFE_RELEASE(p) { if(p) { (p)->Release(); (p)=NULL; } }
#endif

#define STATUS_INFO_LENGTH_MISMATCH	((NTSTATUS) 0xC0000004)
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)

#define CODEINTEGRITY_OPTION_ENABLED 0x01
#define CODEINTEGRITY_OPTION_TESTSIGN 0x02
