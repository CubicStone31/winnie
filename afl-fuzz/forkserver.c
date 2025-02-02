// Winnie Forkserver
//
// This file provides a Windows forkserver using the injected forkserver technique.
// The injected forkserver supports three main modes: dry-run, fork mode, and persistent mode.

#include <Windows.h>
#include <winternl.h>
#include <shlwapi.h>
#include <shlobj.h>
#include <stdio.h>

#include <forklib.h>

#include "types.h"
#include "config.h"
#include "debug.h"
#include "alloc-inl.h"
#include "afl.h"
#include "process.h"
#include "forkserver.h"
#include "stdlib.h"

#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "Dbghelp.lib")

// Print if debug enabled
#define debug_printf(...) {if (options.debug_mode) printf(__VA_ARGS__); }

static void pause()
{
#ifdef _DEBUG
    printf("Press any key to resume...\n");
    _getch();
#endif
}

static volatile HANDLE child_handle, child_thread_handle;

static char* afl_pipe; // forkserver pipename

// Fullspeed fuzzing variables
static bool child_entrypoint_reached;
static uintptr_t base_address;

static bool found_instrumentation = false;
static u32 total_bbs = 0;
static u32 visited_bbs = 0;

static LPVOID pCall_offset;
static HMODULE hModule; // Remove base address of our injected forkserver dll
static LPVOID pFuzzer_settings, pForkserver_state; // Remote address of forkserver exports
static CONTEXT lcContext;

#define USAGE_CHECK(condition, message) if(!(condition)) FATAL("%s\n", message);

typedef struct _module_info_t {
    char module_name[MAX_PATH];
	int index;
    struct _module_info_t *next;
} module_info_t;

static module_info_t *coverage_modules = NULL, *coverage_modules_tail = NULL;

forkserver_option_t options;

static volatile HANDLE hPipeChild;

void load_bbs();

// Parse options from the command line
void forkserver_options_init(int argc, const char *argv[])
{
	child_handle = NULL;
	child_thread_handle = NULL;
	
    int i;
    const char *token;
    
    /* default values */
    options.debug_mode       = false;
    options.coverage_kind    = COVERAGE_BB;
    options.fuzz_harness[0]  = 0;
	options.enable_wer       = true;
	use_fork = true;

	if (!SUCCEEDED(SHGetFolderPathA(NULL, CSIDL_LOCAL_APPDATA, NULL, 0, options.minidump_path))) {
		FATAL("Failed to get %localappdata% path?");
	}
	strncat_s(options.minidump_path, sizeof(options.minidump_path), "\\CrashDumps", strlen("\\CrashDumps"));

	for (i = 0; i < argc; i++) {
		token = argv[i];
		if (strcmp(token, "-harness") == 0) {
			USAGE_CHECK((i + 1) < argc, "missing harness module name");
			strncpy(options.fuzz_harness, argv[++i], sizeof(options.fuzz_harness));
		} else if (strcmp(token, "-nofork") == 0) {
			use_fork = false;
		} else if (strcmp(token, "-debug") == 0) {
			options.debug_mode = true;
		} else if (strcmp(token, "-no_minidumps") == 0) {
			options.enable_wer = false;
		} else if (strcmp(token, "-minidump_dir") == 0) {
			USAGE_CHECK((i + 1) < argc, "missing directory path");
			strncpy(options.minidump_path, argv[++i], sizeof(options.minidump_path));
        } else {
            FATAL("UNRECOGNIZED FORKSERVER OPTION: \"%s\"\n", token);
        }
    }

#ifdef _DEBUG
	options.debug_mode = true;
#endif

	if (!*options.fuzz_harness) {
		FATAL("No harness module specified!\n");
	}
}

// Collect coverage for this module
static module_info_t *get_coverage_module(char *module_name) {
    module_info_t *current_module = coverage_modules;
    while (current_module) {
        if (_stricmp(module_name, current_module->module_name) == 0) {
            return current_module;
        }
        current_module = current_module->next;
    }
    return NULL;
}

static module_info_t* add_coverage_module(char *module_name) {
	module_info_t *module = malloc(sizeof(module_info_t));
	if (strlen(module_name) >= sizeof(module->module_name))
		FATAL("Module name too long: %s\n", module_name);
	module->next = NULL;
	strncpy(module->module_name, module_name, sizeof(module->module_name));
	if (coverage_modules_tail) {
		module->index = coverage_modules_tail->index + 1;
		coverage_modules_tail->next = module;
		coverage_modules_tail = module;
	} else {
		module->index = 0;
		coverage_modules = coverage_modules_tail = module;
	}
	return module;
}

static void add_breakpoint(struct _module_info_t* module, uintptr_t rva, int offset, unsigned char original_opcode, int type) {
	//printf("ADD: %x, %d, %x\n", address, offset, original_opcode);
	struct winafl_breakpoint *new_breakpoint = (struct winafl_breakpoint *)malloc(sizeof(struct winafl_breakpoint));

	new_breakpoint->rva = rva;
	new_breakpoint->file_offset = offset;
	new_breakpoint->original_opcode = original_opcode;
	new_breakpoint->module = module;
	new_breakpoint->type = type;
	new_breakpoint->visited = false;
	new_breakpoint->id = total_bbs++;

	if ((new_breakpoint->id>>3) >= MAP_SIZE)
		FATAL("Too many breakpoints\n");

	new_breakpoint->next = breakpoints;
	breakpoints = new_breakpoint;
}

void load_bbs(char *bbfile)
{
	FILE *bb_fp = fopen(bbfile, "r");
	if (!bb_fp)
		FATAL("Missing basic blocks file %s", bbfile);
	fseek(bb_fp, 0, SEEK_SET);
	char line[65535];
	module_info_t* cur_module = NULL;

	for (int i = 0; fgets(line, 1024, bb_fp); i++)
	{
		if (line[0] == '[')
		{
			int len = strlen(line);
			if (line[len - 2] != ']') // 1 for null, 1 for newline
				FATAL("Malformed basic blocks input line: %s", line);
			line[len - 2] = 0;
			char* module_name = line + 1;
			if (!(cur_module = get_coverage_module(module_name)))
			{
				cur_module = add_coverage_module(module_name);
			}
		}

		if (!cur_module)
			FATAL("Basic blocks input file: syntax error, no module name specified: %s\n", line);

		int j = 0;
		uintptr_t rva, fo;
		for (const char* tok = strtok(line, ","); tok && *tok; tok = strtok(NULL, ",\n"))
		{
			switch (j++)
			{
			case 0:
				sscanf(tok, "%p", &rva);
				break;
			case 1:
				sscanf(tok, "%p", &fo);
				add_breakpoint(cur_module, rva, fo, 0, BREAKPOINT_BB);
				break;
			default:
				FATAL("Malformed basic blocks input line: %s\n", tok);
			}
		}
	}

	fclose(bb_fp);

	if (!coverage_modules_tail) {
		FATAL("No coverage modules specified in basic blocks file\n");
	}
}

typedef char(*cov_modules_list)[MAX_PATH]; // pointer to array

// Return value must be freed!
static cov_modules_list serialize_coverage_modules(_Out_ size_t *size)
{
	if (!coverage_modules_tail) {
		FATAL("No coverage information provided\n");
	}
	int num_modules = coverage_modules_tail->index + 1;
	cov_modules_list module_names = malloc(*size = MAX_PATH * num_modules);
	for (module_info_t* mod = coverage_modules; mod; mod = mod->next) {
		if (mod->index >= num_modules)
			FATAL("Overflow\n");
		strncpy(module_names[mod->index], mod->module_name, MAX_PATH);
	}
	for (int i = 0; i < num_modules; i++)
		debug_printf("Found module: [%s]\n", module_names[i]);
	return module_names;
}

// Return value must be freed!
// module_names must be pointers in FORKSERVER'S ADDRESS SPACE NOT AFL'S
static AFL_COVERAGE_INFO* serialize_breakpoints(cov_modules_list module_names, _Out_ size_t* size) {
	size_t arrsize = total_bbs - visited_bbs;
	debug_printf("Total: %d, visited; %d\n", total_bbs, visited_bbs);
	AFL_COVERAGE_INFO* out = malloc(*size = sizeof(AFL_COVERAGE_INFO) + arrsize * sizeof(struct AFL_BASIC_BLOCK));
	out->NumberOfBasicBlocks = arrsize;
	struct winafl_breakpoint *current = breakpoints;
	int i = 0;
	while (current) {
		if (current->visited != true) {
			if (i >= arrsize)
				FATAL("Overflow\n");
			out->BasicBlocks[i].ModuleName = module_names[current->module->index];
			out->BasicBlocks[i].Rva = current->rva;
			i++;
		}
		current = current->next;
	}
	return out;
}

void Debug_DumpBPInfo()
{
	FILE* f = fopen("bpinfo.txt", "w+");
	for (struct winafl_breakpoint* current = breakpoints; current; current = current->next)
	{	
		fprintf(f, "%s:\t0x%p\n", current->module->module_name, (void*)current->rva);
	}
	fclose(f);
}

static void mark_visited_breakpoint(struct AFL_COVERAGE_PACKET* bp) {
	debug_printf("Got coverage: %s+%p\n", bp->ModuleName, bp->Rva);
	int count = 0;
	bool found = false;
	for (struct winafl_breakpoint *current = breakpoints; current; current = current->next) {
		count += 1;
		if (current->rva == bp->Rva && !stricmp(current->module->module_name, bp->ModuleName)) {
			found_instrumentation = true;
			found = true;
			if (!current->visited) {
				unsigned byte_idx = current->id >> 3;
				if (byte_idx >= MAP_SIZE)
					FATAL("Overflow");
				trace_bits[byte_idx] |= 1 << (current->id & 0x7);
				debug_printf("add trace.\n");
				visited_bbs++;
				current->visited = true;
			}
			break;
		}
	}
}

void get_coverage_info(u32 *visited_bbs_out, u32 *total_bbs_out) {
	*visited_bbs_out = visited_bbs;
	*total_bbs_out = total_bbs;
}

DWORD GetMainThreadId(DWORD pid) {
	auto snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
	THREADENTRY32 tEntry;
	tEntry.dwSize = sizeof(THREADENTRY32);
	DWORD result = 0;
	DWORD currentPID = pid;
	for (BOOL success = Thread32First(snap, &tEntry);
		!result && success && GetLastError() != ERROR_NO_MORE_FILES;
		success = Thread32Next(snap, &tEntry))
	{
		if (tEntry.th32OwnerProcessID == currentPID) {
			result = tEntry.th32ThreadID;
		}
	}
	CloseHandle(snap);
	return result;
}

void kill_process() {
	TerminateProcess(child_handle, 0);
	WaitForSingleObject(child_handle, INFINITE);
	
	CancelIoEx(child_thread_handle, NULL);
	
	CloseHandle(hPipeChild);
	CloseHandle(child_handle);
    CloseHandle(child_thread_handle);

    child_handle = NULL;
    child_thread_handle = NULL;
	hModule = NULL;
	hPipeChild = NULL;	
}

#define FORKSERVER_DLL "forkserver.dll"

int get_child_result()
{
	AFL_FORKSERVER_RESULT forkserverResult;
	do
	{
		DWORD nRead;
		if (!ReadFile(hPipeChild, &forkserverResult, sizeof(forkserverResult), &nRead, NULL) || nRead != sizeof(forkserverResult))
		{
			WARNF("Lost connection to the forkserver (broken pipe), failed to read forkserver result\n");
			return DEBUGGER_ERROR;
		}
		if (forkserverResult.StatusCode == AFL_CHILD_COVERAGE)
		{
			mark_visited_breakpoint(&forkserverResult.CoverageInfo);
		}
		// trace_printf("Forkserver result: %d\n", forkserverResult.StatusCode);
	} while (forkserverResult.StatusCode == AFL_CHILD_COVERAGE);

	switch (forkserverResult.StatusCode)
	{
	case AFL_CHILD_SUCCESS:
		return DEBUGGER_PROCESS_EXIT;
	case AFL_CHILD_TIMEOUT:
		return DEBUGGER_HANGED;
	case AFL_CHILD_CRASHED:
		return DEBUGGER_CRASHED;
	default:
		FATAL("Unexpected forkserver result %d\n", forkserverResult.StatusCode);
	}

	// !!!! The child is now waiting on YOU to kill it! Remember to kill it!
}

UINT64 GetProcessBaseAddress(HANDLE processHandle)
{
	UINT64   baseAddress = 0;
	HMODULE* moduleArray;
	LPBYTE      moduleArrayBytes;
	DWORD       bytesRequired;

	if (processHandle)
	{
		if (EnumProcessModules(processHandle, NULL, 0, &bytesRequired))
		{
			if (bytesRequired)
			{
				moduleArrayBytes = (LPBYTE)LocalAlloc(LPTR, bytesRequired);

				if (moduleArrayBytes)
				{
					unsigned int moduleCount;

					moduleCount = bytesRequired / sizeof(HMODULE);
					moduleArray = (HMODULE*)moduleArrayBytes;

					if (EnumProcessModules(processHandle, moduleArray, bytesRequired, &bytesRequired))
					{
						baseAddress = moduleArray[0];
					}

					LocalFree(moduleArrayBytes);
				}
			}
		}
	}
	return baseAddress;
}

// my winnie entry here
CLIENT_ID spawn_child_with_injection(char* cmd, INJECTION_MODE injection_type, uint32_t timeout, uint32_t init_timeout)
{
	if (!strstr(cmd, "Attach:"))
	{
		dank_perror("Only allow attach mode!");
	}

	char* target = strstr(cmd, "Attach:") + strlen("Attach:");
	ACTF("Entering attach mode, target %s", target);
	ACTF("Please launch your target, and then continue.");
	system("pause");
	// trying to find launched target
	auto snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	PROCESSENTRY32 entry;
	entry.dwSize = sizeof(entry);
	DWORD pid = 0;
	if (!Process32First(snap, &entry))
	{
		dank_perror("Process32FirstW failed.");
	}
	if (strstr(entry.szExeFile, target))
	{
		pid = entry.th32ProcessID;
		binary_name = entry.szExeFile;
		CloseHandle(snap);
	}
	else
	{
		while (Process32Next(snap, &entry))
		{
			if (strstr(entry.szExeFile, target))
			{
				pid = entry.th32ProcessID;
				binary_name = entry.szExeFile;
				break;
			}
		}
		CloseHandle(snap);
	}
	if (pid == 0)
	{
		dank_perror("Attach target not found.");
	}
	ACTF("Found target, pid %d", pid);

	// open target process
	child_handle = OpenProcess(PROCESS_ALL_ACCESS, false, pid);
	if (!child_handle)
	{
		dank_perror("Attach mode: OpenProcess");
	}

	// job settings. now disabled
	{
		ACTF("Apply job settings to the process.");
		JOBOBJECT_EXTENDED_LIMIT_INFORMATION job_limit;
		HANDLE hJob = CreateJobObject(NULL, NULL);
		if (hJob == NULL)
		{
			FATAL("CreateJobObject failed, GLE=%d.\n", GetLastError());
		}
		ZeroMemory(&job_limit, sizeof(job_limit));
		if (mem_limit || cpu_aff)
		{
			if (mem_limit)
			{
				job_limit.BasicLimitInformation.LimitFlags |= JOB_OBJECT_LIMIT_PROCESS_MEMORY;
				job_limit.ProcessMemoryLimit = (size_t)(mem_limit * 1024 * 1024);
			}

			if (cpu_aff)
			{
				job_limit.BasicLimitInformation.LimitFlags |= JOB_OBJECT_LIMIT_AFFINITY;
				job_limit.BasicLimitInformation.Affinity = (DWORD_PTR)cpu_aff;
			}
		}
		//job_limit.BasicLimitInformation.LimitFlags |= JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
		//if (!SetInformationJobObject(hJob, JobObjectExtendedLimitInformation, &job_limit, sizeof(job_limit))) {
		//	SAYF("SetInformationJobObject failed, GLE=%d.\n", GetLastError());
		//}
		//if (!AssignProcessToJobObject(hJob, child_handle)) {
		//	SAYF("AssignProcessToJobObject failed, GLE=%d.\n", GetLastError());
		//}
		CloseHandle(hJob);
	}

	// suspend target's main thread
	child_thread_handle = OpenThread(THREAD_ALL_ACCESS, FALSE, GetMainThreadId(pid));
	if (!child_thread_handle)
	{
		dank_perror("Attach mode: OpenThread");
	}
	if (-1 == SuspendThread(child_thread_handle))
	{
		dank_perror("Attach mode: SuspendThread");
	}
	child_entrypoint_reached = true;
	SAYF("Target process and thread are successfully opened and suspended.\n");

	// get the name of the pipe/event
	afl_pipe = alloc_printf(AFL_FORKSERVER_PIPE "-%d", pid);
	SAYF("  Pipe name: %s\n", afl_pipe);
	// Actually inject the dll now.
	char* injectedDll = FORKSERVER_DLL;
	char szDllFilename[MAX_PATH];
	GetModuleFileNameA(NULL, szDllFilename, sizeof(szDllFilename));
	PathRemoveFileSpecA(szDllFilename);
	strncat(szDllFilename, "\\", max(0, MAX_PATH - strlen(szDllFilename) - 1));
	strncat(szDllFilename, injectedDll, max(0, MAX_PATH - strlen(szDllFilename) - 1));
	debug_printf("  Injecting %s\n", szDllFilename);
	hModule = InjectDll(child_handle, szDllFilename);
	if (!hModule)
	{
		FATAL("InjectDll");
	}
	SAYF("  Forkserver dll injected, base address = %p\n", hModule);

	// Write coverage info
	HANDLE hMapping = INVALID_HANDLE_VALUE, hFile = INVALID_HANDLE_VALUE;
	BYTE* lpBase = NULL;
	PIMAGE_NT_HEADERS ntHeader = map_pe_file(szDllFilename, (LPVOID*)&lpBase, &hMapping, &hFile);
	if (!ntHeader)
		FATAL("Failed to parse PE header of %s", injectedDll);
	DWORD off_fuzzer_settings = get_proc_offset((char*)lpBase, "fuzzer_settings");
	DWORD off_forkserver_state = get_proc_offset((char*)lpBase, "forkserver_state");
	DWORD off_call_target = get_proc_offset((char*)lpBase, "call_target");
	if (!off_fuzzer_settings || !off_call_target)
		FATAL("Fail to locate forkserver exports!\n");
	SAYF("  fuzzer_settings offset = %08x, off_forkserver_state = %08x, call_target offset = %08x\n", off_fuzzer_settings, off_forkserver_state, off_call_target);
	size_t nWritten;
	pFuzzer_settings = (LPVOID)((uintptr_t)hModule + off_fuzzer_settings);
	pForkserver_state = (LPVOID)((uintptr_t)hModule + off_forkserver_state);
	pCall_offset = (LPVOID)((uintptr_t)hModule + off_call_target);
	SAYF("  fuzzer_settings = %p, forkserver_state = %p, call target = %p\n", pFuzzer_settings, pForkserver_state, pCall_offset);
	LPVOID pCovInfo;
	if (use_fullspeed) // Fullspeed mode
	{
		LPVOID pModuleNames;
		{
			size_t module_names_size;
			cov_modules_list module_names = serialize_coverage_modules(&module_names_size);
			pModuleNames = VirtualAllocEx(child_handle, NULL, module_names_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
			if (!pModuleNames)
			{
				dank_perror("Allocating coverage modules list into child");
			}
			if (!WriteProcessMemory(child_handle, pModuleNames, module_names, module_names_size, &nWritten) || nWritten < module_names_size)
			{
				dank_perror("Writing coverage modules list into child");
			}
			free(module_names);
		}
		size_t cov_info_size;
		AFL_COVERAGE_INFO* cov_info = serialize_breakpoints(pModuleNames, &cov_info_size);
		pCovInfo = VirtualAllocEx(child_handle, NULL, cov_info_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
		if (!pCovInfo)
		{
			dank_perror("Allocating basic blocks list into child");
		}
		if (!WriteProcessMemory(child_handle, pCovInfo, cov_info, cov_info_size, &nWritten) || nWritten < cov_info_size)
		{
			dank_perror("Writing basic blocks list into child");
		}
		free(cov_info);
	}
	else if (use_intelpt)
	{
		// Intelpt mode uses external tracing for coverage
		pCovInfo = NULL;
	}
	else
	{
		FATAL("Unsupported coverage mode");
	}
	AFL_SETTINGS fuzzer_settings;
	strncpy(fuzzer_settings.harness_name, options.fuzz_harness, sizeof(fuzzer_settings.harness_name));
	strncpy(fuzzer_settings.minidump_path, options.minidump_path, sizeof(fuzzer_settings.minidump_path));
	fuzzer_settings.timeout = timeout;
	fuzzer_settings.mode = injection_type;
	fuzzer_settings.cov_info = pCovInfo;
	fuzzer_settings.enableWER = options.enable_wer;
	fuzzer_settings.cpuAffinityMask = cpu_aff;
	fuzzer_settings.debug = options.debug_mode;
	if (!WriteProcessMemory(child_handle, pFuzzer_settings, &fuzzer_settings, sizeof(AFL_SETTINGS), &nWritten) || nWritten < sizeof(AFL_SETTINGS))
	{
		dank_perror("Writing fuzzer settings into child");
	}	
	if (lpBase) UnmapViewOfFile((LPCVOID)lpBase);
	if (hMapping != INVALID_HANDLE_VALUE) CloseHandle(hMapping);
	if (hFile != INVALID_HANDLE_VALUE) CloseHandle(hFile);
	// Signal to forkserver that coverage info is written
	FORKSERVER_STATE ready = FORKSERVER_READY;
	if (!WriteProcessMemory(child_handle, pForkserver_state, &ready, sizeof(FORKSERVER_STATE), &nWritten) || nWritten < sizeof(FORKSERVER_STATE))
	{
		dank_perror("Writing fuzzer settings into child");
	}

	// Connect to AFL_FORKSERVER pipe.
	// Wait for forkserver to setup hooks before we resume the main thread.
	ACTF("Connecting to forkserver...");
	DWORD timeElapsed = 0;
	do
	{
		hPipeChild = CreateFileA(afl_pipe, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
		if (hPipeChild == INVALID_HANDLE_VALUE)
		{
			if (GetLastError() == ERROR_FILE_NOT_FOUND)
			{
				Sleep(10);
				timeElapsed += 10;
				if (timeElapsed > init_timeout)
				{
					FATAL("Forkserver failed to initialize!\n");
				}
				continue;
			}
			dank_perror("CreateFileA");
		}
	} while (hPipeChild == INVALID_HANDLE_VALUE);
	DWORD dwMode = PIPE_READMODE_MESSAGE;
	if (!SetNamedPipeHandleState(hPipeChild, &dwMode, NULL, NULL))
	{
		dank_perror("SetNamedPipeHandleState");
	}
	ACTF("Connected to forkserver.");
	SAYF("Ok, the forkserver is ready. Resuming the main thread now.\n");	
	return (CLIENT_ID){ child_handle, child_thread_handle };
}

void resume_child()
{
	ResumeThread(child_thread_handle);
}

//////////////////////////
// FORK MODE  
//////////////////////////
DWORD spawn_forkserver(char** argv, uint32_t timeout, uint32_t init_timeout)
{
	char *cmd = argv_to_cmd(argv);
	spawn_child_with_injection(cmd, FORK, timeout, init_timeout);
	resume_child();
	return GetProcessId(child_handle);
}

CHILD_IDS fork_new_child() {
	AFL_FORKSERVER_REQUEST forkserverRequest;
	DWORD nWritten;
	forkserverRequest.Operation = AFL_CREATE_NEW_CHILD;
	if (!WriteFile(hPipeChild, &forkserverRequest, sizeof(forkserverRequest), &nWritten, NULL) || nWritten != sizeof(forkserverRequest))
	{
		WARNF("Broken forkserver pipe, WriteFile");
		return (CHILD_IDS){0, 0};
	}

	// get the child process info and resume the child
	AFL_FORKSERVER_RESULT forkserverResult;
	DWORD nRead;
	if (!ReadFile(hPipeChild, &forkserverResult, sizeof(forkserverResult), &nRead, NULL) || nRead != sizeof(forkserverResult))
	{
		WARNF("Broken forkserver pipe\n");
		return (CHILD_IDS) { 0, 0 };
	}
	if (forkserverResult.StatusCode != AFL_CHILD_CREATED)
	{
		WARNF("Unexpected forkserver result %d\n", forkserverResult.StatusCode);
	}
	return (CHILD_IDS) { forkserverResult.ChildInfo.ProcessId, forkserverResult.ChildInfo.ThreadId };
}

int fork_run_child()
{
	AFL_FORKSERVER_REQUEST forkserverRequest;
	DWORD nWritten;
	forkserverRequest.Operation = AFL_RESUME_CHILD;
	if (!WriteFile(hPipeChild, &forkserverRequest, sizeof(forkserverRequest), &nWritten, NULL) || nWritten != sizeof(forkserverRequest))
	{
		WARNF("Broken forkserver pipe, failed to send forkserver request");
		return 0;
	}
	return 1;
}

//////////////////////////
// PERSISTENT MODE  
//////////////////////////
void reset_persistent() {
	kill_process();
	persistent_pid = -1;
}

void read_result_persistent(AFL_PERSISTENT_RESULT* persistentResult) {
	//trace_printf("persistent id:%d\n", persistent_pid);
	persistentResult->StatusCode = AFL_CHILD_SUCCESS;
	do
	{
		DWORD nRead;
		if (!ReadFile(hPipeChild, persistentResult, sizeof(*persistentResult), &nRead, NULL) || nRead != sizeof(*persistentResult))
		{
			// persistent mode just reset the server
			persistentResult->StatusCode = AFL_CHILD_CRASHED;
			break;
		}
		if (persistentResult->StatusCode == AFL_CHILD_COVERAGE)
		{
			mark_visited_breakpoint(&persistentResult->CoverageInfo);
		}
	} while (persistentResult->StatusCode == AFL_CHILD_COVERAGE);
	if (persistentResult->StatusCode == AFL_CHILD_CRASHED)
	{
		reset_persistent();
	}
}

void start_persistent(char** argv, uint32_t timeout, uint32_t init_timeout)
{
	char *cmd = argv_to_cmd(argv);
	spawn_child_with_injection(cmd, PERSISTENT, timeout, init_timeout);
	resume_child();
	persistent_pid = GetProcessId(child_handle);

	debug_printf("Waiting for the persistent-mode server to launch\n");

	DWORD timeElapsed = 0;
	while (1)
	{
		SIZE_T nRead;
		FORKSERVER_STATE forkserver_state;
		if (!ReadProcessMemory(child_handle, pForkserver_state, &forkserver_state, sizeof(FORKSERVER_STATE), &nRead) || nRead < sizeof(FORKSERVER_STATE))
		{
			dank_perror("Reading pForkserver_state from child");
		}
		if (forkserver_state == FORKSERVER_WAITING)
		{
			break;
		}
		Sleep(10);
		timeElapsed += 10;
		if (timeElapsed > init_timeout)
		{
			FATAL("Persistent-mode server failed to initialize!\n");
		}
	}

	debug_printf("OK! Capturing the child thread context.\n");

	// One time back up the context
	SuspendThread(child_thread_handle);
	lcContext.ContextFlags = CONTEXT_ALL;
	GetThreadContext(child_thread_handle, &lcContext);
	debug_printf("Captured context at IP=%p\n", lcContext.INSTRUCTION_POINTER);

	FORKSERVER_STATE forkserver_state = FORKSERVER_READY;
	SIZE_T nWritten;
	if (!WriteProcessMemory(child_handle, pForkserver_state, &forkserver_state, sizeof(FORKSERVER_STATE), &nWritten) || nWritten < sizeof(FORKSERVER_STATE))
	{
		dank_perror("Writing pForkserver_state into child");
	}

	// No need to resume here. We will resume in run_with_persistent()
}

int get_ret_val_persistent(code) {
	//switch (forkserverResult.StatusCode)
	switch (code)
	{
	case AFL_CHILD_SUCCESS:
		return DEBUGGER_PROCESS_EXIT;
	case AFL_CHILD_TIMEOUT:
		return DEBUGGER_HANGED;
	case AFL_CHILD_CRASHED:
		return DEBUGGER_CRASHED;
	default:
		FATAL("Unexpected forkserver result %d\n", code);
	}
}

int run_with_persistent() {
	trace_printf("Do persistent run\n");
	// Set the context back
	lcContext.ContextFlags = CONTEXT_ALL;
	if (!SetThreadContext(child_thread_handle, &lcContext))
	{
		dank_perror("SetThreadContext");
	}
	ResumeThread(child_thread_handle); // We assume the thread is already suspended (either by us or by itself)

	AFL_PERSISTENT_RESULT persistentResult;
	read_result_persistent(&persistentResult); // it SHOULD self-suspend at report_ends
	WaitForSingleObject(child_thread_handle, 1); // ???
	return get_ret_val_persistent(persistentResult.StatusCode);
}
