/* x86_64-w64-mingw32-gcc EnablePriv.c -o EnablePriv.exe -municode */
#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>

int wmain(int argc, wchar_t *argv[]) {
    /* Check for specified arguments and print help menu */
    if (argc < 2) {
        wprintf(L"Usage: .\\EnablePriv.exe <privilege>\n");
        return 0;
    }
    
    LUID luid; // Store the LUID received from LookupPrivilegeValueW
    /* Get the LUID for the specified privilege */
    if(!LookupPrivilegeValueW(NULL, argv[1], &luid)) {
        wprintf(L"[+] LookupPrivilegeValueW ERROR (%d)\n", GetLastError());
        return 0;
    } else {
        wprintf(L"[+] LookupPrivilegeValueW OK\n");
    }
    
    /* Configure TOKEN_PRIVILEGES */
    TOKEN_PRIVILEGES tp;
    tp.PrivilegeCount = 1; // Holds a single privilege at a time
    tp.Privileges[0].Luid = luid; // Set the Luid property to the LUID of the privilege obtained from LookupPrivilegeValueW
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED; // Enable Privilege
    
    /* Take snapshot of all processes */
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    PROCESSENTRY32W pe;
    pe.dwSize = sizeof(PROCESSENTRY32);
    int ppid = -1; // Holds the variable of the parent process ID
    if (Process32FirstW(hSnapshot, &pe)) {
        while(Process32NextW(hSnapshot, &pe)) {
            if (pe.th32ProcessID == GetCurrentProcessId()) {
                ppid = pe.th32ParentProcessID; // Get the parent process of the current executing process PID
                break;
            }
        }
    }
    
    /* Get a HANDLE for the parent process */
    HANDLE pHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, ppid);
    if (!pHandle) {
        wprintf(L"[!] OpenProcess ERROR (%d)\n", GetLastError());
        return 0;
    } else {
        wprintf(L"[+] OpenProcess OK\n");
    }
    
    /* Open the parent process token */
    HANDLE tHandle;
    if (!OpenProcessToken(pHandle, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &tHandle)) {
        wprintf(L"[!] OpenProcessToken ERROR (%d)\n", GetLastError());
        return 0;
    } else {
        wprintf(L"[+] OpenProcessToken OK\n");
    }
    
    /* Enable privilege for the parent process */
    if (!AdjustTokenPrivileges(tHandle, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), NULL, NULL)) {
        wprintf(L"[!] AdjustTokenPrivileges ERROR (%d)\n", GetLastError());
        return 0;
    } else {
        wprintf(L"[+] AdjustTokenPrivileges OK\n");
    }
    
    return 0;
}
