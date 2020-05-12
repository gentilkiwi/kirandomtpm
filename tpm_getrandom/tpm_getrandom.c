#include "tpm_getrandom.h"

int wmain(int argc, wchar_t * argv[])
{
	ULONG cbBytesWanted;

	if(argc > 1)
	{
		if(!_wcsicmp(argv[1], L"install"))
			RegisterRngProvider();
		else if(!_wcsicmp(argv[1], L"remove"))
			UnregisterRngProvider();
		else if(!_wcsicmp(argv[1], L"list"))
			ListRngProviders();
		else
		{
			cbBytesWanted = wcstoul(argv[1], NULL, 0);
			if(cbBytesWanted)
			{
				if(argc > 2)
					GetRandomFromLib(cbBytesWanted);
				else GetRandom(cbBytesWanted);
			}
			else PRINT_ERROR(L"Invalid size (%s)\n", argv[1]);
		}
	}
	else PrintUsage(argv[0]);

	return 0;
}

const PWSTR AlgorithmNames[] = {BCRYPT_RNG_ALGORITHM};
const CRYPT_INTERFACE_REG AlgorithmClass = {BCRYPT_RNG_INTERFACE, CRYPT_LOCAL, ARRAYSIZE(AlgorithmNames), (PWSTR *) AlgorithmNames}, *AlgorithmClasses[] = {(PCRYPT_INTERFACE_REG) &AlgorithmClass};;
const CRYPT_IMAGE_REG UserModeImage = {KIRANDOMTPM_PROV_LIB, ARRAYSIZE(AlgorithmClasses), (PCRYPT_INTERFACE_REG *) AlgorithmClasses};
const CRYPT_PROVIDER_REG Provider = {0, NULL, (PCRYPT_IMAGE_REG) &UserModeImage, NULL};
NTSTATUS RegisterRngProvider()
{
	NTSTATUS status;

	kprintf(L"Installing RNG provider `%s`: ", KIRANDOMTPM_PROV_NAME);
	status = BCryptRegisterProvider(KIRANDOMTPM_PROV_NAME, CRYPT_OVERWRITE, (PCRYPT_PROVIDER_REG) &Provider);
	if(status == ERROR_SUCCESS)
	{
		status = BCryptAddContextFunctionProvider(CRYPT_LOCAL, NULL, BCRYPT_RNG_INTERFACE, BCRYPT_RNG_ALGORITHM, KIRANDOMTPM_PROV_NAME, CRYPT_PRIORITY_BOTTOM);
		if(status == ERROR_SUCCESS)
			kprintf(L"OK\n");
		else PRINT_ERROR(L"BCryptAddContextFunctionProvider: 0x%08x\n", status);
	}
	else PRINT_ERROR(L"BCryptRegisterProvider: 0x%08x\n", status);

	return status;
}

NTSTATUS UnregisterRngProvider()
{
	NTSTATUS status;

	kprintf(L"Removing RNG provider `%s`: ", KIRANDOMTPM_PROV_NAME);
	status = BCryptRemoveContextFunctionProvider(CRYPT_LOCAL, NULL, BCRYPT_RNG_INTERFACE, BCRYPT_RNG_ALGORITHM, KIRANDOMTPM_PROV_NAME);
	if(status == ERROR_SUCCESS)
	{
		status = BCryptUnregisterProvider(KIRANDOMTPM_PROV_NAME);
		if(status == ERROR_SUCCESS)
			kprintf(L"OK\n");
		else PRINT_ERROR(L"BCryptUnregisterProvider: 0x%08x\n", status);
	}
	else PRINT_ERROR(L"BCryptRemoveContextFunctionProvider: 0x%08x\n", status);

	return status;
}

NTSTATUS ListRngProviders()
{
	NTSTATUS status;
	ULONG cbProvBuff, i;
	PCRYPT_PROVIDER_REFS pProviderRefs;
	
	kprintf(L"User mode RNG algorithm(s):\n");
	status = BCryptResolveProviders(NULL, BCRYPT_RNG_INTERFACE, BCRYPT_RNG_ALGORITHM, NULL, CRYPT_UM, CRYPT_ALL_PROVIDERS, &cbProvBuff, NULL);
	if(status == ERROR_SUCCESS)
	{
		pProviderRefs = (PCRYPT_PROVIDER_REFS) LocalAlloc(LPTR, cbProvBuff);
		if(pProviderRefs)
		{
			status = BCryptResolveProviders(NULL, BCRYPT_RNG_INTERFACE, BCRYPT_RNG_ALGORITHM, NULL, CRYPT_UM, CRYPT_ALL_PROVIDERS, &cbProvBuff, &pProviderRefs);
			if(status == ERROR_SUCCESS)
			{
				for(i = 0; i < pProviderRefs->cProviders; i++)
					kprintf(L" | %s\n", pProviderRefs->rgpProviders[i]->pszProvider);
			}
			else PRINT_ERROR(L"BCryptResolveProviders(data): 0x%08x\n", status);
			LocalFree(pProviderRefs);
		}
		else status = NTE_NO_MEMORY;
	}
	else PRINT_ERROR(L"BCryptResolveProviders(init): 0x%08x\n", status);

	return status;
}

NTSTATUS GetRandom(DWORD cbBytesWanted)
{
	NTSTATUS status;
	BCRYPT_ALG_HANDLE hAlgorithm;
	PBYTE pBuffer;

	kprintf(L"Retrieving %u random byte%s from `%s` provider: ", cbBytesWanted, (cbBytesWanted > 1) ? L"s" : L"", KIRANDOMTPM_PROV_NAME);
	status = BCryptOpenAlgorithmProvider(&hAlgorithm, BCRYPT_RNG_ALGORITHM, KIRANDOMTPM_PROV_NAME, 0);
	if(status == ERROR_SUCCESS)
	{
		pBuffer = (PBYTE) LocalAlloc(LPTR, cbBytesWanted);
		if(pBuffer)
		{
			status = BCryptGenRandom(hAlgorithm, pBuffer, cbBytesWanted, 0);
			if(status == ERROR_SUCCESS)
				PrintResult(pBuffer, cbBytesWanted);
			else PRINT_ERROR(L"BCryptGenRandom: 0x%08x\n", status);
			LocalFree(pBuffer);
		}
		status = BCryptCloseAlgorithmProvider(hAlgorithm, 0);
		if(status != ERROR_SUCCESS)
			PRINT_ERROR(L"BCryptCloseAlgorithmProvider: 0x%08x\n", status);
	}
	else PRINT_ERROR(L"BCryptOpenAlgorithmProvider: 0x%08x\n", status);

	return status;
}

NTSTATUS GetRandomFromLib(DWORD cbBytesWanted)
{
	NTSTATUS status;
	BCRYPT_RNG_FUNCTION_TABLE *pFunctionTable;
	BCRYPT_ALG_HANDLE hAlgorithm;
	PBYTE pBuffer;

	kprintf(L"Retrieving %u random byte%s from `%s` library: ", cbBytesWanted, (cbBytesWanted > 1) ? L"s" : L"", KIRANDOMTPM_PROV_LIB);
	status = GetRngInterface(NULL, &pFunctionTable, 0);
	if(status == ERROR_SUCCESS)
	{
		status = pFunctionTable->OpenAlgorithmProvider(&hAlgorithm, NULL, 0);
		if(status == ERROR_SUCCESS)
		{
			pBuffer = (PBYTE) LocalAlloc(LPTR, cbBytesWanted);
			if(pBuffer)
			{
				status = pFunctionTable->GenRandom(hAlgorithm, pBuffer, cbBytesWanted, 0);
				if(status == ERROR_SUCCESS)
					PrintResult(pBuffer, cbBytesWanted);
				else PRINT_ERROR(L"GenRandom: 0x%08x\n", status);
				LocalFree(pBuffer);
			}
			status = pFunctionTable->CloseAlgorithmProvider(hAlgorithm, 0);
			if(status != ERROR_SUCCESS)
				PRINT_ERROR(L"CloseAlgorithmProvider: 0x%08x\n", status);
		}
		else PRINT_ERROR(L"OpenAlgorithmProvider: 0x%08x\n", status);
	}
	else PRINT_ERROR(L"GetRngInterface: 0x%08x\n", status);

	return status;
}

void PrintResult(LPCBYTE buffer, DWORD size)
{
	DWORD i;
	kprintf(L"\n\n");
	for(i = 0; i < size; i++)
		kprintf(L"%02x", buffer[i]);
	kprintf(L"\n");
}

void PrintUsage(LPCWSTR szProgram)
{
	kprintf(L"Program usages:\n"
		L"\n %s bytesWanted [noreg]\n\n"
		L"  Retrieve a specified amount of bytes from the registered `%s` provider\n"
		L"  | if noreg argument is specified, the provider is loaded from the current `%s` DLL (without registration)\n\n"
		L"\n %s install\n\n"
		L"  Install the `%s` provider on the system\n"
		L"  | needs administrator rights\n"
		L"  | needs to push `%s` DLL in System32 directory (and SysWOW64 if Win32 support needed on x64 platform)\n\n"
		L"\n %s remove\n\n"
		L"  Remove the `%s` provider from the system\n"
		L"  | needs administrator rights\n"
		L"  | can remove `%s` DLL from System32 directory (and SysWOW64 if Win32 support was needed on x64 platform)\n\n"
		L"\n %s list\n\n"
		L"  List all RNG providers of the system\n\n",
		szProgram, KIRANDOMTPM_PROV_NAME, KIRANDOMTPM_PROV_LIB,
		szProgram, KIRANDOMTPM_PROV_NAME, KIRANDOMTPM_PROV_LIB,
		szProgram, KIRANDOMTPM_PROV_NAME, KIRANDOMTPM_PROV_LIB,
		szProgram);
}