#include <iostream>
#include <fstream>
#include <windows.h>
#include <filesystem>
#include <vector>
#include <math.h>

#define okay(msg, ...) printf("[+] " msg " \n",##__VA_ARGS__)
#define info(msg, ...) printf("[*] " msg " \n",##__VA_ARGS__)
#define warn(msg, ...) printf("[!] " msg " \n",##__VA_ARGS__)
#define error(msg, ...) printf("[!!!] " msg " \n",##__VA_ARGS__)
namespace fs = std::filesystem;

HANDLE GetProcHandle(DWORD PID = NULL); 
std::vector<fs::path> ListDlls();

int main(int argc, char *argv[]){
    HMODULE hKernel{GetModuleHandleW(L"Kernel32")}; // Get module handle for Kernel32.dll
    
    if(hKernel == NULL){                // Check if acquired handle for Kernel32.dll
        error("Failed to acquire Kernel32.dll handle");
        return 1;
    }
    
    if(argc>1){                         // Get Process Handle
        GetProcHandle(atoi(argv[1]));
    }
    else{
        GetProcHandle();
    } 
    

    // VirtualAllocEx();
    // WriteProcessMemory();
    // CreateRemoteThread();


    return 0;
}


HANDLE ValidateProcHandle(DWORD PID){
    HANDLE hProcess{0};
    if(PID%4 != 0 || PID == 0){
        warn("Invalid PID Given");
        return NULL;
    }

    hProcess = OpenProcess(PROCESS_ALL_ACCESS, false, PID);

    if(hProcess == NULL){
        warn("Failed to acquire handle. Error Code: 0x%lx", GetLastError());
        return NULL;
    }
    return hProcess;
}


HANDLE GetProcHandle(DWORD PID){ 
    HANDLE hProcess{0};
    if(PID != NULL){
        hProcess = ValidateProcHandle(PID);
    }
    while(hProcess == NULL){
        std::cout << "Please Insert a PID (Program ID) of the program you want to inject: ";
        std::cin >> PID;
        hProcess = ValidateProcHandle(PID);
    };
    okay("Acquired process handle! %lu", hProcess);
    return hProcess;
}


std::vector<fs::path> ListDlls(){
    std::vector<fs::path> files{};
    fs::path where{fs::current_path()};
    // std::cout << "Found the following DLL files. Please input number to toggle: \n";
    int counter{0};
    for(auto const &file : fs::recursive_directory_iterator(where)){
        if(file.is_directory() == false && file.path().filename().extension() == ".dll"){
            counter++;
            files.push_back(file);
            // std::cout << counter << ". " << file.path().filename().string() << std::endl;
        }
    }
    



    return files;
}


