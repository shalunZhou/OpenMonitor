//
// Autthor: shalunZhou
//

#include "ApcInject.h"

std::vector<DWORD> GetPidByProcessName(wchar_t *pszProcessName) {
	std::vector<DWORD> pids = {};

    PROCESSENTRY32 pe32 = { 0 };
	::RtlZeroMemory(&pe32, sizeof(pe32));
	pe32.dwSize = sizeof(pe32);

	HANDLE hSnapshot = ::CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (NULL == hSnapshot) {
		return std::move(pids);
	}

	BOOL bRet = ::Process32First(hSnapshot, &pe32);
	while (bRet){
		if (0 == ::lstrcmpi(pe32.szExeFile, pszProcessName)){
			pids.emplace_back(pe32.th32ProcessID);
		}

		bRet = ::Process32Next(hSnapshot, &pe32);
	}

	return std::move(pids);
}


std::vector<DWORD> GetTidByPid(const DWORD& pid){
    std::vector<DWORD> tids = {};

    THREADENTRY32 te32 = { 0 };
    ::RtlZeroMemory(&te32, sizeof(te32));
    te32.dwSize = sizeof(te32);

	HANDLE hSnapshot = ::CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (NULL == hSnapshot) {
        return std::move(tids);
    }

    BOOL bRet = ::Thread32First(hSnapshot, &te32);
    while (bRet) {
        if (te32.th32OwnerProcessID == pid) {
            tids.emplace_back(te32.th32ThreadID);
        }

        bRet = ::Thread32Next(hSnapshot, &te32);
    }

    return std::move(tids);
}

BOOL ApcInject(const DWORD& pid, const std::wstring& dll_path){
    auto tids = GetTidByPid(pid);
	HANDLE hProcess = NULL;
	PVOID pBaseAddress = NULL;
	BOOL bRet = FALSE;


	do 
	{
        hProcess = ::OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
        if (!hProcess) {
			break;
        }

        pBaseAddress = VirtualAllocEx(hProcess, NULL, dll_path.length(), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if (!pBaseAddress) {
			break;
        }

		DWORD dwRet = 0;
		WriteProcessMemory(hProcess, pBaseAddress, dll_path.c_str(), dll_path.length(), &dwRet);
		if (dwRet != dll_path.length()) {
			break;
		}

		PVOID pLoadLibrary = GetProcAddress(GetModuleHandle(L"kernel32.dll"), "LoadLibraryW");
		if (!pLoadLibrary){
			break;
		}

		//之所以向所有线程都注入APC的目的是为了只要任一线程被唤醒，就能立刻注入。
        for (const auto & tid :tids){
            HANDLE hThread = ::OpenThread(THREAD_ALL_ACCESS, FALSE, tid);
            if (hThread){
                QueueUserAPC((PAPCFUNC)pLoadLibrary, hThread, (ULONG_PTR)pBaseAddress);

                CloseHandle(hThread);
                hThread = NULL;
            }
        }

	} while (false);

    if (hProcess)
    {
        ::CloseHandle(hProcess);
        hProcess = NULL;
    }

	return bRet;
}

int wmain(int argc,wchar_t*argv[]){

	if(argc < 1){
		return -1;
	}

	if (argc == 3){
		std::wstring dll_path = argv[2];

		auto pids = GetPidByProcessName(argv[1]);

		for (const auto & pid : pids){
			ApcInject(pid, dll_path);
		}
	}

	return 0;
}



