/*
* Author:   shalunZhou
* Desc:     Apc Inject   
* Date:     2023/11/09
* =================================================
*/
#pragma once
#include <Windows.h>
#include <TlHelp32.h>
#include <vector>
#include <string>


std::vector<DWORD> GetPidByProcessName(wchar_t* pszProcessName);

std::vector<DWORD> GetTidByPid(const DWORD& pid);

BOOL ApcInject(const DWORD& pid, const std::wstring & dll_path);