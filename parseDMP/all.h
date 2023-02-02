#pragma once
#include <ntstatus.h>
#define WIN32_NO_STATUS
#define SECURITY_WIN32
#define CINTERFACE
#define COBJMACROS
#include <windows.h>
#include <sspi.h>
#include <sddl.h>
#include <ntsecapi.h>
#include <ntsecpkg.h>
#include <stdio.h>
#include <wchar.h>

#define NET_MODULE

#if defined(_M_X64)
	#define mypw_ARCH L"x64"
#elif defined(_M_IX86)
	#define mypw_ARCH L"x86"
#endif

#if !defined(NT_SUCCESS)
#define NT_SUCCESS(Status) ((NTSTATUS)(Status) >= 0)
#endif

#define LM_NTLM_HASH_LENGTH	16

#define PW_M_WIN_BUILD_XP		2600
#define PW_M_WIN_BUILD_2K3	3790
#define PW_M_WIN_BUILD_VISTA	6000
#define PW_M_WIN_BUILD_7		7600
#define PW_M_WIN_BUILD_8		9200
#define PW_M_WIN_BUILD_BLUE	9600
#define PW_M_WIN_BUILD_10_1507	10240
#define PW_M_WIN_BUILD_10_1511	10586
#define PW_M_WIN_BUILD_10_1607	14393
#define PW_M_WIN_BUILD_10_1703	15063
#define PW_M_WIN_BUILD_10_1709	16299
#define PW_M_WIN_BUILD_10_1803	17134
#define PW_M_WIN_BUILD_10_1809	17763
#define PW_M_WIN_BUILD_10_1903	18362
#define PW_M_WIN_BUILD_10_1909	18363
#define PW_M_WIN_BUILD_10_2004	19041
#define PW_M_WIN_BUILD_10_20H2	19042
#define PW_M_WIN_BUILD_10_21H2	19044
#define PW_M_WIN_BUILD_2022		20348

#define PW_M_WIN_MIN_BUILD_XP		2500
#define PW_M_WIN_MIN_BUILD_2K3	3000
#define PW_M_WIN_MIN_BUILD_VISTA	5000
#define PW_M_WIN_MIN_BUILD_7		7000
#define PW_M_WIN_MIN_BUILD_8		8000
#define PW_M_WIN_MIN_BUILD_BLUE	9400
#define PW_M_WIN_MIN_BUILD_10		9800
#define PW_M_WIN_MIN_BUILD_11		22000
