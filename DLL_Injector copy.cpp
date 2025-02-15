#include <iostream>
#include <fstream>
#include <windows.h>
#include <filesystem>
#include <vector>
#include <math.h>
#include <map>


#define okay(msg, ...) printf("[+] " msg " \n",##__VA_ARGS__)
#define info(msg, ...) printf("[*] " msg " \n",##__VA_ARGS__)
#define warn(msg, ...) printf("[!] " msg " \n",##__VA_ARGS__)
#define error(msg, ...) printf("[!!!] " msg " \n",##__VA_ARGS__)

int main(){
    HANDLE PROCESS{OpenProcess(PROCESS_ALL_ACCESS, false, 48644)};
    std::string FILE{"D:\\VSCode Programs\\Git\\DLL_Injector\\DLLs\\Bow.dll"};
    info("Now attempting injection into the target process");    
    HMODULE hKernel{GetModuleHandleW(L"Kernel32")}; // Get module handle for Kernel32.dll

    if(hKernel == NULL){ // Check if acquired handle for Kernel32.dll
        error("Inject_DLL: Failed to acquire Kernel32.dll handle. \n Error code: 0x%lX", GetLastError());
    }
    LPTHREAD_START_ROUTINE LoadLib{(LPTHREAD_START_ROUTINE) GetProcAddress(hKernel, "LoadLibraryW")}; // Thread routine

    LPVOID rBuffer{};
    rBuffer = VirtualAllocEx(PROCESS, NULL, FILE.size()+1, (MEM_COMMIT | MEM_RESERVE), PAGE_EXECUTE_READWRITE);

    if(rBuffer == NULL){
        error("Inject_DLL: Failed to allocate memory in target process. \n Error code: 0x%lX", GetLastError());
        CloseHandle(hKernel);
    }
    info("Successfully allocated memory in target process!");    
    
    WriteProcessMemory(PROCESS, rBuffer, FILE.data(), FILE.size()+1, NULL);

    info("Successfully written to memory in target process!");    
    HANDLE hThread{CreateRemoteThread(PROCESS, NULL, 0, LoadLib, rBuffer, 0, NULL)};
    WaitForSingleObject(hThread, INFINITE);

    if(hThread == NULL){
        error("Inject_DLL: Failed to create remote thread in target process. \n Error code: 0x%lX", GetLastError());
        CloseHandle(hKernel);
    }
    info("Successfully created remote thread in target process! \n");    

    HMODULE ExitCode{};

    

    GetExitCodeThread(hThread, (DWORD *)&ExitCode);

    info("Starting Deallocation");

    if(hKernel == NULL){ // Check if acquired handle for Kernel32.dll
        error("Inject_DLL: Failed to acquire Kernel32.dll handle. \n Error code: 0x%lX", GetLastError());
        CloseHandle(hKernel);
    }

    size_t Bytes{};

    if(WriteProcessMemory(PROCESS, rBuffer, &ExitCode, sizeof(&ExitCode), &Bytes) == 0){
        error("cant write handle :( Error: %lX", GetLastError());
    }
    info("Bytes written: %lld", Bytes);

    LPTHREAD_START_ROUTINE FreeLib{(LPTHREAD_START_ROUTINE) GetProcAddress(hKernel, "FreeLibrary")}; // Thread routine
    if(FreeLib == NULL){
        warn("FreeLibrary could not be found! Error Code: 0x%lX", GetLastError()); 
        CloseHandle(hKernel);
    }
    info("MemPage: %llX", rBuffer);

    HMODULE* Argument{ new HMODULE };
    Argument = (HMODULE *)rBuffer;

    hThread = CreateRemoteThread(PROCESS, NULL, 0, FreeLib, Argument, 0, NULL);

    WaitForSingleObject(hThread, INFINITE);
    GetExitCodeThread(hThread, (DWORD *)&ExitCode);

    if(ExitCode == 0){
        warn("Could not free library. Error code: 0x%lX", GetLastError());
        delete ExitCode;
        CloseHandle(hKernel);
        CloseHandle(hThread);
    }


    info("freed successfully!");

    CloseHandle(hKernel);
    CloseHandle(hThread);
    info("Deallocated memory page successfully!\n");

    return true;
}