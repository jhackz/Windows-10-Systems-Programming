#include "Header.h"

// Taken from chapter 3
bool EnableDebugPrivilege() 
{
	HANDLE hToken;

	if (!::OpenProcessToken(::GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken))
	{
		return false;
	}

	TOKEN_PRIVILEGES tp;
	tp.PrivilegeCount = 1;
	tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

	if (!::LookupPrivilegeValue(nullptr, SE_DEBUG_NAME, &tp.Privileges[0].Luid))
	{
		return false;
	}

	if (!::AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), nullptr, nullptr))
	{
		return false;
	}

	return ::GetLastError() == ERROR_SUCCESS;
}


BOOL TermProc(DWORD pid)
{
	BOOL status = FALSE;
	HANDLE hProcess = NULL;

	// Get a handle to the process we want terminated
	hProcess = ::OpenProcess(PROCESS_TERMINATE, FALSE, pid);

	if (hProcess == NULL)
	{
		printf("[-] OpenProcess: %08x\n", ::GetLastError());
	}

	else
	{
		// Tell the process "I'll be back"
		if (::TerminateProcess(hProcess, 0))
		{
			// Ensure the process was terminated
			if (::WaitForSingleObject(hProcess, INFINITE) == WAIT_OBJECT_0)
			{
				// This should be set
				status = TRUE;
			}
		}

		else
		{
			printf("[-] TerminateProcess: %08x\n", ::GetLastError());
		}
	}

	return status;
}


int main()
{
	DWORD pid;
	NTSTATUS status;
	PSYSTEM_PROCESS_INFO spi;
	PVOID procBuffer;
	ULONG returnLength;

	if (!EnableDebugPrivilege())
	{
		printf("[-] Failed to endable debug privileges\n");
	}


	// Get our return length with our first call to NtQuerySystemInfromation
	if (!NT_SUCCESS(status = ::NtQuerySystemInformation(SystemProcessInformation, NULL, NULL, &returnLength)))
	{
		// Allocate our buffer of size returnLength here
		procBuffer = ::VirtualAlloc(NULL, returnLength, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

		if (procBuffer == NULL)
		{
			printf("[-] VirtualAlloc: %08x\n", ::GetLastError());
			return -1;
		}

		spi = (PSYSTEM_PROCESS_INFO)procBuffer;
		if (!NT_SUCCESS(status = ::NtQuerySystemInformation(SystemProcessInformation, spi, returnLength, NULL)))
		{
			printf("[-] NtQuerySystemInformation: %08x\n", status);
			::VirtualFree(procBuffer, 0, MEM_RELEASE);
			return -1;
		}

		// Iterate over the entire list 
		while (spi->NextEntryOffset) 
		{
			printf("[*] %ws\n\t[+] PID: %p\n\t[+] Handle Count: %lu\n\t[+] Session ID: %lu\n\t[+] Threads: %lu\n\t\t\n",
				spi->ImageName.Buffer, 
				spi->UniqueProcessId, 
				spi->HandleCount, 
				spi->SessionId, 
				spi->NumberOfThreads); 

			// Pull the start addresses of all the threads per process. 
			for (ULONG i = 0; i < spi->NumberOfThreads; i++)
			{
				printf("\t\t\t[%x] Start Address: %p\n", i, spi->Threads[i].StartAddress);
			}

			// Get our next entry 
			spi = (PSYSTEM_PROCESS_INFO)((LPBYTE)spi + spi->NextEntryOffset); 
		}

		printf("\n[*] Enter a PID to terminate: ");
		scanf_s("%d", &pid);

		// TerminateProcess wrapper
		if (!TermProc(pid))
		{
			printf("[-] TermProc Failed -_-\n");
		}

		::VirtualFree(procBuffer, 0, MEM_RELEASE);

	}

	else
	{
		printf("[-] NtQuerySystemInformation: %08x\n", status);
		return -1;
	}

	return 0;
}