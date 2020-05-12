/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : https://creativecommons.org/licenses/by/4.0/
*/
#include "kirandomtpmprov.h"

__checkReturn NTSTATUS WINAPI KiwiBCryptOpenAlgorithmProvider(__out BCRYPT_ALG_HANDLE *phAlgorithm, __in LPCWSTR pszAlgId, __in ULONG dwFlags)
{
	NTSTATUS status = NTE_INTERNAL_ERROR;
	PKIWI_RANDOMTPM_HANDLE pProvider = NULL;
	TBS_CONTEXT_GENERIC_PARAMS ContextParams;

	UNREFERENCED_PARAMETER(pszAlgId);
	UNREFERENCED_PARAMETER(dwFlags);

	if(phAlgorithm)
	{
		pProvider = (PKIWI_RANDOMTPM_HANDLE) LocalAlloc(LPTR, sizeof(KIWI_RANDOMTPM_HANDLE));
		if(pProvider)
		{
			ContextParams.v1.version = TBS_CONTEXT_VERSION_ONE;
			status = Tbsi_Context_Create(&ContextParams.v1, &pProvider->hContext);
			if(status == TBS_SUCCESS)
			{
				pProvider->tpmVersion = TPM_VERSION_12;
				*phAlgorithm = pProvider;
			}
			else if(status == TBS_E_TPM_NOT_FOUND)
			{
				ContextParams.v2.version = TBS_CONTEXT_VERSION_TWO;
				ContextParams.v2.asUINT32 = 0;
				ContextParams.v2.includeTpm20 = 1;
				status = Tbsi_Context_Create((PCTBS_CONTEXT_PARAMS) &ContextParams.v2, &pProvider->hContext);
				if(status == TBS_SUCCESS)
				{
					pProvider->tpmVersion = TPM_VERSION_20;
					*phAlgorithm = pProvider;
				}
			}

			if(status != TBS_SUCCESS)
				LocalFree(pProvider);
		}
		else status = NTE_NO_MEMORY;
	}
	else status = NTE_INVALID_PARAMETER;

	return status;
}

__checkReturn NTSTATUS WINAPI KiwiBCryptCloseAlgorithmProvider(__inout BCRYPT_ALG_HANDLE hAlgorithm, __in ULONG dwFlags)
{
	NTSTATUS status = NTE_INTERNAL_ERROR;

	UNREFERENCED_PARAMETER(hAlgorithm);
	UNREFERENCED_PARAMETER(dwFlags);

	if(hAlgorithm)
	{
		status = Tbsip_Context_Close(((PKIWI_RANDOMTPM_HANDLE) hAlgorithm)->hContext);
		LocalFree(hAlgorithm);
	}
	else status = NTE_INVALID_HANDLE;

	return status;
}

__checkReturn NTSTATUS WINAPI KiwiBCryptGenRandom(__in_opt BCRYPT_ALG_HANDLE hAlgorithm, __inout_bcount_full(cbBuffer) PUCHAR pbBuffer, __in ULONG cbBuffer, __in ULONG dwFlags)
{
	NTSTATUS status = NTE_INTERNAL_ERROR;
	TPM_GetRandom_Command Command;
	TPM_GetRandom_Response Response;
	GetRandomRawFn GetRandomRaw;
	UINT32 cbRead;

	UNREFERENCED_PARAMETER(dwFlags);

	if(hAlgorithm)
	{
		if(pbBuffer && cbBuffer)
		{
			switch(((PKIWI_RANDOMTPM_HANDLE) hAlgorithm)->tpmVersion)
			{
			case TPM_VERSION_12:
				Command.v12.tag = _byteswap_ushort(TPM_TAG_RQU_COMMAND);
				Command.v12.paramSize = _byteswap_ulong(sizeof(TPM12_GetRandom_Command));
				Command.v12.ordinal = _byteswap_ulong(TPM_ORD_GetRandom);
				GetRandomRaw = GetRandomRaw12;
				break;
			case TPM_VERSION_20:
				Command.v20.tag = _byteswap_ushort(TPM_ST_NO_SESSIONS);
				Command.v20.commandSize = _byteswap_ulong(sizeof(TPM20_GetRandom_Command));
				Command.v20.commandCode = _byteswap_ulong(TPM_CC_GetRandom);
				GetRandomRaw = GetRandomRaw20;
				break;
			default:
				GetRandomRaw = NULL;
			}

			if(GetRandomRaw)
			{
				while(cbBuffer)
				{
					status = GetRandomRaw(((PKIWI_RANDOMTPM_HANDLE) hAlgorithm)->hContext, &Command, cbBuffer, &Response, pbBuffer, &cbRead);
					if(status == TBS_SUCCESS)
					{
						cbBuffer -= cbRead;
						pbBuffer += cbRead;
					}
					else break;
				}
			}
		}
		else status = NTE_INVALID_PARAMETER;
	}
	else status = NTE_INVALID_HANDLE;

	return status;
}

NTSTATUS GetRandomRaw12(__in TBS_HCONTEXT hContext, __in PTPM_GetRandom_Command pCommand, __in UINT32 cbBytesWanted, __inout PTPM_GetRandom_Response pResponse, __inout PUCHAR pbBuffer, __out PUINT32 pcbBytesRead)
{
	NTSTATUS status;
	UINT32 cbResponse = sizeof(TPM12_GetRandom_Response);

	pCommand->v12.bytesRequested = _byteswap_ulong(min(cbBytesWanted, sizeof(TPM12_GetRandom_Response) - FIELD_OFFSET(TPM12_GetRandom_Response, bytes)));
	status = Tbsip_Submit_Command(hContext, TBS_COMMAND_LOCALITY_ZERO, TBS_COMMAND_PRIORITY_NORMAL, (PCBYTE) pCommand, sizeof(TPM12_GetRandom_Command), (PBYTE) pResponse, &cbResponse);
	if(status == TBS_SUCCESS)
	{
		if((pResponse->v12.tag == _byteswap_ushort(TPM_TAG_RSP_COMMAND)) && (pResponse->v12.returnCode == TPM_SUCCESS))
		{
			*pcbBytesRead = min(_byteswap_ulong(pResponse->v12.randomBytesSize), cbBytesWanted);
			CopyMemory(pbBuffer, pResponse->v12.bytes, *pcbBytesRead);
		}
		else status = TBS_E_INTERNAL_ERROR;
	}
	
	return status;
}

NTSTATUS GetRandomRaw20(__in TBS_HCONTEXT hContext, __in PTPM_GetRandom_Command pCommand, __in UINT32 cbBytesWanted, __inout PTPM_GetRandom_Response pResponse, __inout PUCHAR pbBuffer, __out PUINT32 pcbBytesRead)
{
	NTSTATUS status;
	UINT32 cbResponse = sizeof(TPM20_GetRandom_Response);

	pCommand->v20.bytesRequested = _byteswap_ushort((UINT16) min(cbBytesWanted, sizeof(TPM20_GetRandom_Response) - FIELD_OFFSET(TPM20_GetRandom_Response, bytes)));
	status = Tbsip_Submit_Command(hContext, TBS_COMMAND_LOCALITY_ZERO, TBS_COMMAND_PRIORITY_NORMAL, (PCBYTE) pCommand, sizeof(TPM20_GetRandom_Command), (PBYTE) pResponse, &cbResponse);
	if(status == TBS_SUCCESS)
	{
		if((pResponse->v20.tag == pCommand->v20.tag) && (pResponse->v20.responseCode == TPM_RC_SUCCESS))
		{
			*pcbBytesRead = min(_byteswap_ushort(pResponse->v20.size), cbBytesWanted);
			CopyMemory(pbBuffer, pResponse->v20.bytes, *pcbBytesRead);
		}
		else status = TBS_E_INTERNAL_ERROR;
	}

	return status;
}

__checkReturn NTSTATUS WINAPI KiwiBCryptGetProperty(__in BCRYPT_HANDLE hObject, __in LPCWSTR pszProperty, __out_bcount_part_opt(cbOutput, *pcbResult) PUCHAR pbOutput, __in ULONG cbOutput, __out ULONG *pcbResult, __in ULONG dwFlags)
{
	UNREFERENCED_PARAMETER(hObject);
	UNREFERENCED_PARAMETER(pszProperty);
	UNREFERENCED_PARAMETER(pbOutput);
	UNREFERENCED_PARAMETER(cbOutput);
	UNREFERENCED_PARAMETER(pcbResult);
	UNREFERENCED_PARAMETER(dwFlags);

	return STATUS_NOT_IMPLEMENTED;
}

__checkReturn NTSTATUS WINAPI KiwiBCryptSetProperty(__inout BCRYPT_HANDLE hObject, __in LPCWSTR pszProperty, __in_bcount(cbInput) PUCHAR pbInput, __in ULONG cbInput, __in ULONG dwFlags)
{
	UNREFERENCED_PARAMETER(hObject);
	UNREFERENCED_PARAMETER(pszProperty);
	UNREFERENCED_PARAMETER(pbInput);
	UNREFERENCED_PARAMETER(cbInput);
	UNREFERENCED_PARAMETER(dwFlags);

	return STATUS_NOT_IMPLEMENTED;
}

const BCRYPT_RNG_FUNCTION_TABLE KiwiRngFunctionTable = {
	BCRYPT_RNG_INTERFACE_VERSION_1,
	KiwiBCryptOpenAlgorithmProvider,
	KiwiBCryptGetProperty,
	KiwiBCryptSetProperty,
	KiwiBCryptCloseAlgorithmProvider,
	KiwiBCryptGenRandom
};

__checkReturn __declspec(dllexport) NTSTATUS WINAPI GetRngInterface(__in LPCWSTR pszProviderName, __out BCRYPT_RNG_FUNCTION_TABLE **ppFunctionTable, __in ULONG dwFlags)
{
	UNREFERENCED_PARAMETER(pszProviderName);
	UNREFERENCED_PARAMETER(dwFlags);

	*ppFunctionTable = (BCRYPT_RNG_FUNCTION_TABLE *) &KiwiRngFunctionTable;

	return ERROR_SUCCESS;
}