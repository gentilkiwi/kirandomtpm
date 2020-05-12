#pragma once
#include <stdio.h>
#include <ntstatus.h>
#define WIN32_NO_STATUS
#include <windows.h>

#if !defined(kprintf)
#define kprintf wprintf
#endif

#if !defined(PRINT_ERROR)
#define PRINT_ERROR(...) (kprintf(L"ERROR " TEXT(__FUNCTION__) L" ; " __VA_ARGS__))
#endif

#if !defined(PRINT_ERROR_AUTO)
#define PRINT_ERROR_AUTO(func) (kprintf(L"ERROR " TEXT(__FUNCTION__) L" ; " func L" (0x%08x)\n", GetLastError()))
#endif

int wmain(int argc, wchar_t * argv[]);
NTSTATUS RegisterRngProvider();
NTSTATUS UnregisterRngProvider();
NTSTATUS ListRngProviders();
NTSTATUS GetRandom(DWORD cbBytesWanted);
NTSTATUS GetRandomFromLib(DWORD cbBytesWanted);
void PrintResult(LPCBYTE buffer, DWORD size);
void PrintUsage(LPCWSTR szProgram);

#define KIRANDOMTPM_PROV_NAME	L"Kiwi Random TPM Provider"
#define KIRANDOMTPM_PROV_LIB	L"kirandomtpmprov.dll"

extern __checkReturn NTSTATUS WINAPI BCryptRegisterProvider(__in LPCWSTR pszProvider, __in ULONG dwFlags, __in PCRYPT_PROVIDER_REG pReq);
extern __checkReturn NTSTATUS WINAPI BCryptUnregisterProvider(__in LPCWSTR pszProvider);
extern __checkReturn NTSTATUS WINAPI BCryptAddContextFunctionProvider(__in ULONG dwTable, __in LPCWSTR pszContext, __in ULONG dwInterface, __in LPCWSTR pszFunction, __in LPCWSTR pszProvider, __in ULONG dwPosition);
extern __checkReturn NTSTATUS WINAPI BCryptRemoveContextFunctionProvider(__in ULONG dwTable, __in LPCWSTR pszContext, __in ULONG dwInterface, __in LPCWSTR pszFunction, __in LPCWSTR pszProvider);

typedef __checkReturn NTSTATUS (WINAPI * BCryptOpenAlgorithmProviderFn) (__out BCRYPT_ALG_HANDLE *phAlgorithm, __in LPCWSTR pszAlgId, __in ULONG dwFlags);
typedef __checkReturn NTSTATUS (WINAPI * BCryptGetPropertyFn) (__in BCRYPT_HANDLE hObject, __in LPCWSTR pszProperty, __out_bcount_part_opt(cbOutput, *pcbResult) PUCHAR pbOutput, __in ULONG cbOutput, __out ULONG *pcbResult, __in ULONG dwFlags);
typedef __checkReturn NTSTATUS (WINAPI * BCryptSetPropertyFn) (__inout BCRYPT_HANDLE hObject, __in LPCWSTR pszProperty, __in_bcount(cbInput) PUCHAR pbInput, __in ULONG cbInput, __in ULONG dwFlags);
typedef __checkReturn NTSTATUS (WINAPI * BCryptCloseAlgorithmProviderFn) (__inout BCRYPT_ALG_HANDLE hAlgorithm, __in ULONG dwFlags);
typedef __checkReturn NTSTATUS (WINAPI * BCryptGenRandomFn) (__in_opt BCRYPT_ALG_HANDLE hAlgorithm, __inout_bcount_full(cbBuffer) PUCHAR pbBuffer, __in ULONG cbBuffer, __in ULONG dwFlags);

typedef struct _BCRYPT_RNG_FUNCTION_TABLE {
	BCRYPT_INTERFACE_VERSION		Version;
	BCryptOpenAlgorithmProviderFn	OpenAlgorithmProvider;
	BCryptGetPropertyFn				GetProperty;
	BCryptSetPropertyFn				SetProperty;
	BCryptCloseAlgorithmProviderFn	CloseAlgorithmProvider;
	BCryptGenRandomFn				GenRandom;
} BCRYPT_RNG_FUNCTION_TABLE;

extern __checkReturn NTSTATUS WINAPI GetRngInterface(__in LPCWSTR pszProviderName, __out BCRYPT_RNG_FUNCTION_TABLE **ppFunctionTable, __in ULONG dwFlags);