#pragma once
#include <ntstatus.h>
#define WIN32_NO_STATUS
#include <windows.h>
#include <tbs.h>

#define MAX_RESPONSE_SIZE 1024 // 4096 - To not break 4k/8k local variables limit

/* TPM 1.2 */
typedef UINT16 TPM_TAG;
typedef UINT32 TPM_COMMAND_CODE;
typedef UINT32 TPM_RESULT;

#define TPM_SUCCESS			(TPM_RESULT) (0x00000000)
#define TPM_TAG_RQU_COMMAND	(TPM_TAG) (0x00c1)
#define TPM_TAG_RSP_COMMAND	(TPM_TAG) (0x00c4)
#define TPM_ORD_GetRandom	(TPM_COMMAND_CODE) (0x00000046)

#pragma pack(push, 1)
typedef struct _TPM12_GetRandom_Command {
	TPM_TAG tag;
	UINT32 paramSize;
	TPM_COMMAND_CODE ordinal;
	UINT32 bytesRequested;
} TPM12_GetRandom_Command, *PTPM12_GetRandom_Command;

typedef struct _TPM12_GetRandom_Response {
	TPM_TAG tag;
	UINT32 paramSize;
	TPM_RESULT returnCode;
	UINT32 randomBytesSize;
	BYTE bytes[MAX_RESPONSE_SIZE - (sizeof(TPM_TAG) + sizeof(UINT32) + sizeof(TPM_RESULT) + sizeof(UINT32))];
} TPM12_GetRandom_Response, *PTPM12_GetRandom_Response;
#pragma pack(pop)

/* TPM 2.0 */
typedef UINT16 TPM_ST;
typedef TPM_ST TPMI_ST_COMMAND_TAG;
typedef UINT32 TPM_CC;
typedef UINT32 TPM_RC;

#define TPM_RC_SUCCESS		(TPM_RC) (0x00000000)
#define TPM_ST_NO_SESSIONS	(TPM_ST) (0x8001)
#define TPM_CC_GetRandom	(TPM_CC) (0x0000017b)

#pragma pack(push, 1)
typedef struct _TPM20_GetRandom_Command {
	TPMI_ST_COMMAND_TAG tag;
	UINT32 commandSize;
	TPM_CC commandCode;
	UINT16 bytesRequested;
} TPM20_GetRandom_Command, *PTPM20_GetRandom_Command;

typedef struct _TPM20_GetRandom_Response {
	TPM_ST tag;
	UINT32 responseSize;
	TPM_RC responseCode;
	UINT16 size;
	BYTE bytes[MAX_RESPONSE_SIZE - (sizeof(TPM_ST) + sizeof(UINT32) + sizeof(TPM_RC) + sizeof(UINT16))];
} TPM20_GetRandom_Response, *PTPM20_GetRandom_Response;
#pragma pack(pop)

#pragma warning(push)
#pragma warning(disable:4201) // nonstandard extension used : nameless struct/union

typedef struct _TPM_GetRandom_Command {
	union {
		TPM12_GetRandom_Command v12;
		TPM20_GetRandom_Command v20;
	};
} TPM_GetRandom_Command, *PTPM_GetRandom_Command;

typedef struct _TPM_GetRandom_Response {
	union {
		TPM12_GetRandom_Response v12;
		TPM20_GetRandom_Response v20;
	};
} TPM_GetRandom_Response, *PTPM_GetRandom_Response;

typedef struct _TBS_CONTEXT_GENERIC_PARAMS
{
   union {
		TBS_CONTEXT_PARAMS v1;
		TBS_CONTEXT_PARAMS2 v2;
	};
} TBS_CONTEXT_GENERIC_PARAMS, *PTBS_CONTEXT_GENERIC_PARAMS;

#pragma warning(pop)

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

typedef __checkReturn NTSTATUS (WINAPI * GetRngInterfaceFn)(__in LPCWSTR pszProviderName, __out BCRYPT_RNG_FUNCTION_TABLE **ppFunctionTable, __in ULONG dwFlags);

typedef struct _KIWI_RANDOMTPM_HANDLE {
	TBS_HCONTEXT hContext;
	UINT32 tpmVersion;
} KIWI_RANDOMTPM_HANDLE, *PKIWI_RANDOMTPM_HANDLE;

__checkReturn NTSTATUS WINAPI KiwiBCryptOpenAlgorithmProvider(__out BCRYPT_ALG_HANDLE *phAlgorithm, __in LPCWSTR pszAlgId, __in ULONG dwFlags);
__checkReturn NTSTATUS WINAPI KiwiBCryptGetProperty(__in BCRYPT_HANDLE hObject, __in LPCWSTR pszProperty, __out_bcount_part_opt(cbOutput, *pcbResult) PUCHAR pbOutput, __in ULONG cbOutput, __out ULONG *pcbResult, __in ULONG dwFlags);
__checkReturn NTSTATUS WINAPI KiwiBCryptSetProperty(__inout BCRYPT_HANDLE hObject, __in LPCWSTR pszProperty, __in_bcount(cbInput) PUCHAR pbInput, __in ULONG cbInput, __in ULONG dwFlags);
__checkReturn NTSTATUS WINAPI KiwiBCryptCloseAlgorithmProvider(__inout BCRYPT_ALG_HANDLE hAlgorithm, __in ULONG dwFlags);
__checkReturn NTSTATUS WINAPI KiwiBCryptGenRandom(__in_opt BCRYPT_ALG_HANDLE hAlgorithm, __inout_bcount_full(cbBuffer) PUCHAR pbBuffer, __in ULONG cbBuffer, __in ULONG dwFlags);

__checkReturn __declspec(dllexport) NTSTATUS WINAPI GetRngInterface(__in LPCWSTR pszProviderName, __out BCRYPT_RNG_FUNCTION_TABLE **ppFunctionTable, __in ULONG dwFlags);

typedef NTSTATUS (* GetRandomRawFn) (__in TBS_HCONTEXT hContext, __in PTPM_GetRandom_Command pCommand, __in UINT32 cbBytesWanted, __inout PTPM_GetRandom_Response pResponse, __inout PUCHAR pbBuffer, __out PUINT32 pcbBytesRead);

NTSTATUS GetRandomRaw12(__in TBS_HCONTEXT hContext, __in PTPM_GetRandom_Command pCommand, __in UINT32 cbBytesWanted, __inout PTPM_GetRandom_Response pResponse, __inout PUCHAR pbBuffer, __out PUINT32 pcbBytesRead);
NTSTATUS GetRandomRaw20(__in TBS_HCONTEXT hContext, __in PTPM_GetRandom_Command pCommand, __in UINT32 cbBytesWanted, __inout PTPM_GetRandom_Response pResponse, __inout PUCHAR pbBuffer, __out PUINT32 pcbBytesRead);