#include <stdio.h>
#include <windows.h>
#include <Lmcons.h>

HMODULE loaded_lib;
FARPROC loaded_api;

int main() {
	
	char lib[13];
	char api[13];
	
	TCHAR username[UNLEN + 1];
	DWORD size = UNLEN + 1;
	
	// GetUserNameA
	*(api + 0) = 'G';
	*(api + 1) = 'e';
	*(api + 2) = 't';
	*(api + 3) = 'U';
	*(api + 4) = 's';
	*(api + 5) = 'e';
	*(api + 6) = 'r';
	*(api + 7) = 'N';
	*(api + 8) = 'a';
	*(api + 9) = 'm';
	*(api + 10) = 'e';
	*(api + 11) = 'A';
	*(api + 12) = '\0';
	
	// Advapi32.dll
	*(lib + 0) = 'A';
	*(lib + 1) = 'd';
	*(lib + 2) = 'v';
	*(lib + 3) = 'a';
	*(lib + 4) = 'p';
	*(lib + 5) = 'i';
	*(lib + 6) = '3';
	*(lib + 7) = '2';
	*(lib + 8) = '.';
	*(lib + 9) = 'd';
	*(lib + 10) = 'l';
	*(lib + 11) = 'l';
	*(lib + 12) = '\0';
	
	loaded_lib = LoadLibrary(lib);
	
	loaded_api = GetProcAddress(loaded_lib, api);
	
	printf("Library: %s\n", lib);
	printf("API: %s\n", api);
	
	loaded_api((TCHAR*)username, &size);
	
	printf("Username: %s\n", username);
	
}