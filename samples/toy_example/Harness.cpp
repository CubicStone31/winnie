// cl.exe /D_USERDLL /D_WINDLL Harness.cpp /MT /link /DLL /OUT:Harness.dll

#include <stdio.h>
#include <windows.h>
#include <conio.h>
#include <harness-api.h>

// This macro exports the HARNESS_INFO struct expected by fuzzer. The injected forkserver (injected-harness) will LoadLibrary the harness, and then use this.
EXPOSE_HARNESS(
  NULL,  // target method, we will fill this in dynamically at DllMain
  NULL,  // fuzz iter func, we will fill this in dynamically at DllMain
  NULL,  // default input file (.cur_input)
  NULL,  // no setup func needed
  FALSE, // don't need desocket
  FALSE  // Not ready yet, we initialize dynamically in DllMain.
);

HMODULE hMainModule;
LPVOID fuzzMe;

BOOL APIENTRY DllMain(HMODULE hModule,
	DWORD  ul_reason_for_call,
	LPVOID lpReserved
)
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
		hMainModule = GetModuleHandle(NULL);
		// dnf
		// fuzzMe = (LPVOID)((UINT64)0x434A640 + (UINT64)hMainModule);
		// printf("dnf fuzz target at %p\n", fuzzMe);
		//// kart
		//fuzzMe = (LPVOID)((UINT64)0xE72940 + (UINT64)GetModuleHandleW(L"top-kart.dll"));
		//printf("kart fuzz target at %p\n", fuzzMe);
		// 
		// cf
		// cf_ch_gamesrv.exe
		fuzzMe = (LPVOID)((UINT64)0x46D910 + (UINT64)hMainModule);
		HarnessInfo.target_method = fuzzMe;
		HarnessInfo.fuzz_iter_func = (void (CALLBACK *)(void)) fuzzMe;
		MemoryBarrier(); // Prevent the compiler from messing things up by reordering.
		InterlockedExchange8(&HarnessInfo.ready, TRUE); // Signal to forkserver that we're ready to go.

		break;
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:
		break;
	}
	return TRUE;
}

