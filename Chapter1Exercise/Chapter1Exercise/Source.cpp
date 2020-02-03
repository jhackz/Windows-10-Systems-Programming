// Window's 10 Systems Programing Chapter 1
// Author JHackz

#define BUILD_WINDOWS
#define WIN32_LEAN_AND_MEAN

#include <stdio.h>
#include <Windows.h>


bool CheckVM()
{
	// Quick and dirty VM check using cpuid
	// EAX will have our return value
	__asm
	{
		xor eax, eax
		inc eax
		cpuid
		bt ecx, 0x1f
		mov eax, ecx
	}

	return;
}

BOOL CheckVersionInfo(OSVERSIONINFOEXW *vi)
{
	DWORDLONG conditionMask = 0;
	OSVERSIONINFOW osvi = { sizeof(osvi) };
	int op = VER_GREATER_EQUAL;
	
	::GetVersionExW(&osvi);
	vi->dwOSVersionInfoSize = sizeof(OSVERSIONINFOEXW);
	vi->dwMajorVersion = osvi.dwMajorVersion;
	vi->dwMinorVersion = osvi.dwMinorVersion;

	vi->wServicePackMajor = 0;
	vi->wServicePackMinor = 0;
	
	// Initialize the condition mask.

	VER_SET_CONDITION(conditionMask, VER_MAJORVERSION, op);
	VER_SET_CONDITION(conditionMask, VER_MINORVERSION, op);
	VER_SET_CONDITION(conditionMask, VER_SERVICEPACKMAJOR, op);
	VER_SET_CONDITION(conditionMask, VER_SERVICEPACKMINOR, op);

	return ::VerifyVersionInfoW(
		vi, VER_MAJORVERSION |
		VER_MINORVERSION |
		VER_SERVICEPACKMAJOR |
		VER_SERVICEPACKMINOR,
		conditionMask);
}

// More verbose error output
void ErrorCheck(DWORD err)
{
	LPWSTR text;

	DWORD chars = ::FormatMessageW(
		FORMAT_MESSAGE_ALLOCATE_BUFFER |
		FORMAT_MESSAGE_FROM_SYSTEM |
		FORMAT_MESSAGE_IGNORE_INSERTS,
		nullptr, err, 0,
		(LPWSTR)&text,
		0, nullptr);

	if (chars > 0)
	{
		printf("Error %d: %ws\n", err, text);
		::LocalFree(text);
	}
	else 
	{
		printf("[-] No such error\n");
	}

	return;
}

int main()
{

	DWORD size = MAX_COMPUTERNAME_LENGTH + 1;
	LARGE_INTEGER pc;
	OSVERSIONINFOEXW vi = { sizeof(vi) };
	SYSTEM_INFO si;
	WCHAR computerName[MAX_COMPUTERNAME_LENGTH + 1];
	WCHAR winDir[MAX_PATH];

	if (CheckVM())
	{
		printf("[*] Virtual Environment\n");
	}

	if (!CheckVersionInfo(&vi))
	{
		printf("[-] CheckVersionInfo\n");
		ErrorCheck(::GetLastError());
	}
	else
	{
		printf("[*] OS Major Version: %d\n[*] OS Minor Version: %d\n", 
			vi.dwMajorVersion, 
			vi.dwMinorVersion);
	}
	
	// NativeSystemInfo inside the jungle of if / else
	::GetNativeSystemInfo(&si);

	// I'm sorry this is D:
	printf("[*] Page Size: %d\n[*] Processor Type: %d\n[*] Processor Arch: %d\n[*] Number of Processors: %d\n",
		si.dwPageSize,
		si.dwProcessorType,
		si.wProcessorArchitecture,
		si.dwNumberOfProcessors);

	if (!::QueryPerformanceCounter(&pc))
	{
		printf("[-] QueryPerformanceCounter\n");
		ErrorCheck(::GetLastError());
	}
	else
	{	// This feels wrong because of the size of pc being a LARGE_INT
		printf("[*] Perfromace Counter: %#10.8x\n", pc);
	}

	if (!::GetComputerNameW(computerName, &size))
	{
		printf("[-] GetComputerName\n");
		ErrorCheck(::GetLastError());
	}
	else
	{
		printf("[*] ComputerName: %ws\n", computerName);
	}

	if (!::GetWindowsDirectoryW(winDir, MAX_PATH))
	{
		printf("[-] GetWindowsDirectoryW\n");
		ErrorCheck(::GetLastError());
	}
	else
	{
		printf("[*] Windows Directory: %ws\n", winDir);
	}

	return 0;
}