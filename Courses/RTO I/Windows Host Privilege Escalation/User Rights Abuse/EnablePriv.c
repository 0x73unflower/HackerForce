#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>

int main(int argc, char *argv[]) {
    /* Check for specified arguments and print help menu */
    if (argc < 2) {
        printf("Usage: .\\EnablePriv.exe <privilege>\n");
        return 0;
    }
    
    LUID luid; // Store the LUID received from LookupPrivilegeA in this variable
    // Get the LUID for the specified privilege
    if(!LookupPrivilegeValueA(NULL, argv[1], &luid)) {
        printf("[+] LookupPrivilegeValue ERROR (%d)\n", GetLastError());
        return 0;
    } else {
        printf("[+] LookupPrivilegeValue OK\n");
    }
    
    /* Configure TOKEN_PRIVILEGES */
    TOKEN_PRIVILEGES tp;
    tp.PrivilegeCount = 1; // Holds a single privilege at a time
    tp.Privileges[0].Luid = luid; // Set the Luid property to the LUID of the privilege obtained from LookupPrivilegeValue()
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED; // Enable Privilege
    
    /* Take snapshot of all processes */
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    PROCESSENTRY32 pe;
    pe.dwSize = sizeof(PROCESSENTRY32);
    int ppid = -1; // Holds the variable of the parent process ID
    if (Process32First(hSnapshot, &pe)) {
        while(Process32Next(hSnapshot, &pe)) {
            if (pe.th32ProcessID == GetCurrentProcessId()) {
                ppid = pe.th32ParentProcessID; // Get the parent process of the current executing process PID
                break;
            }
        }
    }
    
    /* Get a HANDLE for the parent process */
    HANDLE pHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, ppid);
    if (!pHandle) {
        printf("[!] OpenProcess ERROR (%d)\n", GetLastError());
        return 0;
    } else {
        printf("[+] OpenProcess OK\n");
    }
    
    /* Open the parent process token */
    HANDLE tHandle;
    if (!OpenProcessToken(pHandle, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &tHandle)) {
        printf("[!] OpenProcessToken ERROR (%d)\n", GetLastError());
        return 0;
    } else {
        printf("[+] OpenProcessToken OK\n");
    }
    
    /* Enable privilege for the parent process */
    if (!AdjustTokenPrivileges(tHandle, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), NULL, NULL)) {
        printf("[!] AdjustTokenPrivileges ERROR (%d)\n", GetLastError());
        return 0;
    } else {
        printf("[+] AdjustTokenPrivileges OK\n");
    }
    
    return 0;
}