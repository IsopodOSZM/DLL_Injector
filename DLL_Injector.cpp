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

enum states {off, once, leave};

HANDLE GetProcHandle(DWORD PID = NULL); 
std::vector<fs::path> Get_DLLs();

int main(int argc, char *argv[]){
    info("Please place DLLs in current directory with executable or in specified directory labelled \"DLLs\" which will be created if one doesnt exist already");
    Get_DLLs();
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
    std::vector<fs::path> filepaths{Get_DLLs()}; // filepaths to DLLs
    size_t filepaths_size{filepaths.size()}; // number of elements in filepaths
    
    std::vector<std::string> filenames{};
    for(const auto &x : filepaths){
        filenames.push_back(x.filename().string());
    }

    std::vector<states> state{}; // states of DLL files. whether they are: 1. not to be injected, 2. whether they are injected once and deallocated or 3. if theyre kept in the program until termination

    for(size_t x{}; x<filepaths_size; x++){
        state.push_back(off);
    }

    std::string input{};
    printf("\n\n\n");
    std::cin.ignore();
    do{
        info("Controls: [q/quit/exit - quit program; r/run - inject DLL(s); rescan - rescan directory for DLLs]");
        info("Found the following DLL files. Please input number to cycle through off/activates once/left on: ");
        
        for(size_t x{}; x<filepaths_size; x++){ // Print all found DLLs and the activated label if they are active.
            switch(state[x]){
                case off:
                    std::cout << std::setw(3) << (x+1) << ". " << std::left << std::setw(50) << filenames[x] << std::right << "\n";
                    break;
                case once:
                    std::cout << std::setw(3) << (x+1) << ". " << std::left << std::setw(50) << filenames[x] << std::right << " (Attach and Detach)" << "\n";
                    break;
                case leave:
                    std::cout << std::setw(3) << (x+1) << ". " << std::left << std::setw(50) << filenames[x] << std::right << " (Attach and Leave on)" << "\n";
                    break;
            }
        }
        std:getline(std::cin, input);


    }while(input!="quit" || input!="q");
    

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

std::vector<fs::path> Get_DLLs(){
    std::vector<fs::path> files{};
    fs::path where{fs::current_path()};
    int counter{0};
    bool *DLL_Folder = new bool;
    *DLL_Folder = false;
    for(auto const &file : fs::recursive_directory_iterator(where)){
        if(file.is_directory() == false && file.path().filename().extension() == ".dll"){
            counter++;
            files.push_back(file);
        } else if (file.is_directory() == true && file.path().filename() == "DLLs"){
            *DLL_Folder = true;
        }
    }
    if(*DLL_Folder != true){
        fs::create_directory(where.append("DLLs"));
    }
    delete DLL_Folder;
    DLL_Folder = nullptr;



    return files;
}


