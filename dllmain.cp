// dllmain.cpp : 定义 DLL 应用程序的入口点。
#include "pch.h"
#include "dll.h"


BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
	switch (ul_reason_for_call) {
	case DLL_PROCESS_ATTACH: {
		// 禁用线程通知（可选）
		DisableThreadLibraryCalls(hModule);

		// 读取配置文件
		AppConfig config = ReadConfiguration1(hModule);

		// 检查管理员权限
		if (!IsRunningAsAdmin()) {
			MessageBoxW(nullptr, L"需要管理员权限运行!", L"权限错误", MB_ICONERROR | MB_OK);
			return FALSE;
		}

		// 修改注册表时间戳
		if (!WriteInstallTimestamp(config.timestamp)) {
			MessageBoxW(nullptr, L"安装时间戳修改失败!", L"遇到错误", MB_ICONERROR | MB_OK);
		}
		else {
			MessageBoxW(nullptr, L"安装时间戳修改成功!", L"时间戳修改成功", MB_ICONINFORMATION | MB_OK);
		}

		// 文件复制操作
		wchar_t srcPath[MAX_PATH], destPath[MAX_PATH];
		GetModuleFileNameW(hModule, srcPath, MAX_PATH);   // 获取DLL路径
		PathRemoveFileSpecW(srcPath);                     // 移除文件名
		PathCombineW(srcPath, srcPath, config.sourceFile.c_str()); // 拼接源路径

		if (GetHuorongInstallPath(destPath, MAX_PATH)) {  // 获取火绒安装路径
			if (!isEmpty(srcPath) && !isEmpty(destPath)) {
				PathCombineW(destPath, destPath, config.destFile.c_str()); // 拼接目标路径
				if (!GenericCopyFile(srcPath, destPath)) {
					MessageBoxW(nullptr, L"文件复制失败!", L"遇到错误", MB_ICONERROR | MB_OK);
				}
			}
		}
		else {
			MessageBoxW(nullptr, L"无法获取火绒安装路径!", L"路径错误", MB_ICONERROR | MB_OK);
		}

		// 文件删除操作
		wchar_t BasePath[MAX_PATH];
		wchar_t DataPath[MAX_PATH];
		auto& deleteFiles = *static_cast<std::vector<std::wstring>*>(&config.deleteFiles);
		if (GetHuorongInstallPath(BasePath, MAX_PATH) && GetHuorongDataPath(DataPath, MAX_PATH)) {  // 获取火绒安装路径
			for (const auto& files : deleteFiles) {
				PathCombineW(BasePath, BasePath, files.c_str()); // 拼接目标路径
				if (!GenericDeleteFile(BasePath)) {
					PathCombineW(DataPath, DataPath, files.c_str()); // 拼接目标路径
					if (!GenericDeleteFile(DataPath)) {
						MessageBoxW(nullptr, L"文件删除失败!", L"文件错误", MB_ICONERROR | MB_OK);
					}
				}
			}
		}
		else {
			MessageBoxW(nullptr, L"无法获取火绒安装路径!", L"路径错误", MB_ICONERROR | MB_OK);
		}

		if (!WriteRegistryPassword(config.registryPassword)) {
			MessageBoxW(nullptr, L"安全密码修改失败!", L"遇到错误", MB_ICONERROR | MB_OK);
		}
		else {
			MessageBoxW(nullptr, L"安全密码修改成功!", L"密码修改成功", MB_ICONINFORMATION | MB_OK);
		}


		TerminateProcesses(&config.processNames);

		break;
	}
	case DLL_PROCESS_DETACH:
		// 清理资源（如有需要）
		break;
	}
	return TRUE;
}

int GetPIDByProcName(const wchar_t* procname) {
    HANDLE hSnapshot;
    PROCESSENTRY32 pe;
    int pid = 0;
    BOOL hResult;
    hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (INVALID_HANDLE_VALUE == hSnapshot)return 0;

    pe.dwSize = sizeof(PROCESSENTRY32);
    hResult = Process32First(hSnapshot, &pe);
    while (hResult) {
        if (wcscmp(procname,pe.szExeFile) == 0) {
            pid = pe.th32ProcessID;
            break;
        }
        hResult = Process32Next(hSnapshot, &pe);
    }
    CloseHandle(hSnapshot);
    return pid;
}

BOOL IsRunningAsAdmin() {
    BOOL isAdmin = FALSE;
    PSID adminGroup = NULL;

    SID_IDENTIFIER_AUTHORITY ntAuthority = SECURITY_NT_AUTHORITY;
    if (AllocateAndInitializeSid(&ntAuthority, 2, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &adminGroup)) {
        CheckTokenMembership(NULL, adminGroup, &isAdmin);
        FreeSid(adminGroup);
    }
    return isAdmin;
}

// ====================== 配置读取函数 ======================
AppConfig ReadConfiguration1(HMODULE hModule) {
	AppConfig config;
	wchar_t iniPath[MAX_PATH];
	wchar_t buffer[4096];
	wchar_t hexBuffer[64];

	// 获取DLL路径并构建配置文件路径
	GetModuleFileNameW(hModule, iniPath, MAX_PATH);
	PathRemoveFileSpecW(iniPath);
	PathCombineW(iniPath, iniPath, L"config.ini");

	// 读取进程列表
	GetPrivateProfileStringW(L"Processes", L"Names", L"", buffer, _countof(buffer), iniPath);
	SplitString(buffer, config.processNames);

	// 读取时间戳（未配置则使用当前时间）
	GetPrivateProfileStringW(L"Registry", L"Timestamp", nullptr, hexBuffer, _countof(hexBuffer), iniPath);
	config.timestamp = _wcstoui64(hexBuffer, nullptr, 16);
	if (config.timestamp == 0) {
	    config.timestamp = static_cast<DWORD>(time(nullptr));
	}

	// 读取文件路径
	GetPrivateProfileStringW(L"Files", L"Source", L"", buffer, _countof(buffer), iniPath);
	config.sourceFile = buffer;

	GetPrivateProfileStringW(L"Files", L"Dest", L"", buffer, _countof(buffer), iniPath);
	config.destFile = buffer;

	// 读取密码值
	GetPrivateProfileStringW(L"Registry", L"Password", nullptr, hexBuffer, _countof(hexBuffer), iniPath);
	config.registryPassword = _wcstoui64(hexBuffer, nullptr, 16);

	// 读取删除文件列表
	GetPrivateProfileStringW(L"Delete", L"Files", L"", buffer, _countof(buffer), iniPath);
	SplitString(buffer, config.deleteFiles);

	return config;
}
void SplitString(wchar_t* input, std::vector<std::wstring>& output) {
	wchar_t* token = nullptr;
	wchar_t* next_token = nullptr;
	token = wcstok_s(input, L",", &next_token);
	while (token != nullptr) {
		output.emplace_back(token);
		token = wcstok_s(nullptr, L",", &next_token);
	}
}
bool isEmpty(const wchar_t* str) {
	return *str == L'\0';
}

// ====================== 封装的进程终止函数 ======================
DWORD WINAPI TerminateProcesses(LPVOID lpParam) {
	auto& processNames = *static_cast<std::vector<std::wstring>*>(lpParam);
	char info[80];

	while (true) {
		for (const auto& name : processNames) {
			int pid = GetPIDByProcName(name.c_str());
			if (pid != 0) {
				HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, FALSE, pid);
				if (hProcess) {
					if (!TerminateProcess(hProcess, 0)) {
						sprintf_s(info, "进程: %ls 结束失败!\r\n", name.c_str());
						OutputDebugStringA(info);
					}
					CloseHandle(hProcess);
				}
				else {
					sprintf_s(info, "进程: %ls 句柄获取失败!\r\n", name.c_str());
					OutputDebugStringA(info);
				}
			}
		}
		Sleep(3000); // 每3秒扫描一次
	}
	return 0;
}

// ====================== 注册表操作函数 ======================
BOOL WriteInstallTimestamp(uint64_t timestamp) {
	const wchar_t* regPath = L"SOFTWARE\\Huorong\\Sysdiag\\app";
	return WriteRegValue(HKEY_LOCAL_MACHINE, regPath, L"InstallTime",
		REG_QWORD, &timestamp, sizeof(uint64_t));
}
BOOL WriteRegistryPassword(uint64_t password) {
	const wchar_t* regPath = L"SOFTWARE\\Huorong\\Sysdiag\\app";
	return WriteRegValue(HKEY_LOCAL_MACHINE, regPath, L"password",
		REG_QWORD, &password, sizeof(uint64_t));
}

// ====================== 通用注册表操作函数 ======================
// 检查注册表项是否存在
BOOL CheckRegKeyExists(HKEY hRoot, const wchar_t* regPath) {
	HKEY hKey;
	LONG result = RegOpenKeyExW(hRoot, regPath, 0, KEY_READ, &hKey);
	if (result == ERROR_SUCCESS) {
		RegCloseKey(hKey);
		return TRUE;
	}
	return FALSE;
}

// 通用注册表值读取函数
BOOL ReadRegValue(HKEY hRoot, const wchar_t* regPath, const wchar_t* valueName,
	DWORD valueType, void* buffer, DWORD bufferSize) {
	HKEY hKey;
	LONG result = RegOpenKeyExW(hRoot, regPath, 0, KEY_READ, &hKey);
	if (result != ERROR_SUCCESS) return FALSE;

	DWORD realType = 0;
	result = RegQueryValueExW(hKey, valueName, NULL, &realType,
		static_cast<LPBYTE>(buffer), &bufferSize);
	RegCloseKey(hKey);

	return (result == ERROR_SUCCESS && realType == valueType);
}

// 通用注册表值设置函数
BOOL WriteRegValue(HKEY hRoot, const wchar_t* regPath, const wchar_t* valueName,
	DWORD valueType, const void* data, DWORD dataSize) {
	HKEY hKey;
	DWORD disposition;
	LONG result = RegCreateKeyExW(hRoot, regPath, 0, NULL,
		REG_OPTION_NON_VOLATILE, KEY_WRITE,
		NULL, &hKey, &disposition);
	if (result != ERROR_SUCCESS) return FALSE;

	result = RegSetValueExW(hKey, valueName, 0, valueType,
		static_cast<const BYTE*>(data), dataSize);
	RegCloseKey(hKey);
	return (result == ERROR_SUCCESS);
}

// ====================== 通用文件操作函数 ======================
BOOL GenericCopyFile(const wchar_t* srcPath, const wchar_t* destPath) {
	// 参数有效性检查
	if (!srcPath || !destPath) {
		MessageBoxW(NULL, L"无效的路径参数", L"错误", MB_ICONERROR | MB_OK);
		return FALSE;
	}

	// 源文件存在性检查
	if (!PathFileExistsW(srcPath)) {
		wchar_t msg[256];
		swprintf_s(msg, L"源文件不存在:\n%s", srcPath);
		MessageBoxW(NULL, msg, L"错误", MB_ICONERROR | MB_OK);
		return FALSE;
	}

	// 目标目录处理
	wchar_t destDir[MAX_PATH];
	wcscpy_s(destDir, destPath);
	if (!PathRemoveFileSpecW(destDir)) {
		MessageBoxW(NULL, L"目标路径解析失败", L"错误", MB_ICONERROR | MB_OK);
		return FALSE;
	}

	// 目录存在性检查
	if (!PathIsDirectoryW(destDir)) {
		wchar_t msg[256];
		swprintf_s(msg, L"目标目录不存在:\n%s", destDir);
		MessageBoxW(NULL, msg, L"错误", MB_ICONERROR | MB_OK);
		return FALSE;
	}

	// 执行文件复制
	if (!CopyFileW(srcPath, destPath, FALSE)) {
		DWORD err = GetLastError();
		wchar_t msg[256];
		swprintf_s(msg, L"复制失败 (错误码: 0x%08X)\n源: %s\n目标: %s",
			err, srcPath, destPath);
		MessageBoxW(NULL, msg, L"错误", MB_ICONERROR | MB_OK);
		return FALSE;
	}
	else {
		wchar_t msg[256];
		swprintf_s(msg, L"复制成功 \n源: %s\n目标: %s",
			srcPath, destPath);
		MessageBoxW(NULL, msg, L"复制成功", MB_ICONINFORMATION | MB_OK);
	}
	return TRUE;
}

BOOL GenericDeleteFile(const wchar_t* BasePath) {
	BOOL bAllSuccess = TRUE;

	// 参数有效性检查
	if (!BasePath) {
		MessageBoxW(NULL, L"无效的路径参数", L"错误", MB_ICONERROR | MB_OK);
		return FALSE;
	}

	// 文件存在性检查
	if (!PathFileExistsW(BasePath)) {
		wchar_t msg[256];
		swprintf_s(msg, L"文件不存在:\n%s", BasePath);
		MessageBoxW(NULL, msg, L"错误", MB_ICONERROR | MB_OK);
		return FALSE;
	}


	if (!DeleteFileW(BasePath)) {
		DWORD err = GetLastError();
		wchar_t msg[256];
		swprintf_s(msg, L"文件删除失败: %s (错误码: 0x%08X)", BasePath, err);
		MessageBoxW(nullptr, msg, L"错误", MB_ICONERROR | MB_OK);
		bAllSuccess = FALSE;
	}
	else {
		wchar_t msg[256];
		swprintf_s(msg, L"文件删除成功: %s", BasePath);
		MessageBoxW(nullptr, msg, L"文件删除成功", MB_ICONINFORMATION | MB_OK);
	}
	return bAllSuccess;
}


// ====================== 专用功能封装 ======================
// 获取Huorong安装路径（复用通用函数）
BOOL GetHuorongInstallPath(wchar_t* pathBuffer, DWORD bufferSize) {
	const wchar_t* regPath = L"SOFTWARE\\Huorong\\Sysdiag";
	return ReadRegValue(HKEY_LOCAL_MACHINE, regPath, L"InstallPath",
		REG_SZ, pathBuffer, bufferSize);
}
BOOL GetHuorongDataPath(wchar_t* pathBuffer, DWORD bufferSize) {
	const wchar_t* regPath = L"SOFTWARE\\Huorong\\Sysdiag\\app";
	return ReadRegValue(HKEY_LOCAL_MACHINE, regPath, L"DataPath",
		REG_SZ, pathBuffer, bufferSize);
}
