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
    Get_DLLs(); // Create folder for DLLs
    HANDLE hProcess{}; // Handle to target process

    if(argc>1){                         // Get Process Handle
        hProcess = GetProcHandle(atoi(argv[1]));
    }
    else{
        hProcess = GetProcHandle();
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
    


    return 0;
}


HANDLE Inject_DLL(const HANDLE hProcess, fs::path DLL_Path, LPDWORD* ThreadID){
    std::string filename{DLL_Path.filename().string()};

    HMODULE hKernel{GetModuleHandleW(L"Kernel32")}; // Get module handle for Kernel32.dll

    if(hKernel == NULL){                            // Check if acquired handle for Kernel32.dll
        error("Inject_DLL: Failed to acquire Kernel32.dll handle for %s. \n Error code: 0x%lX", filename, GetLastError());
        return;
    }
    LPTHREAD_START_ROUTINE LoadLib{(LPTHREAD_START_ROUTINE) GetProcAddress(hKernel, "LoadLibraryW")}; // Thread routine

    wchar_t Wide_DLL_Path[MAX_PATH]{}; // Wide string path to the DLL
    wcscpy(Wide_DLL_Path, str_to_wchar_t(DLL_Path.string())); // Copy string path into wchar array
                                                                
    size_t Wide_DLL_Path_Size{sizeof(Wide_DLL_Path)}; // Size of the Path (since the max is 260 chars, thats how big itll be)
    
    LPVOID rBuffer{};

    rBuffer = VirtualAllocEx(hProcess, NULL, Wide_DLL_Path_Size, (MEM_COMMIT | MEM_RESERVE), PAGE_READWRITE);

    if(rBuffer == NULL){
        error("Inject_DLL: Failed to allocate memory in target process for %s. \n Error code: 0x%lX", filename, GetLastError());
        CloseHandle(hKernel);
        return;
    }
    
    size_t* Bytes_Written{ new size_t };

    WriteProcessMemory(hProcess, rBuffer, Wide_DLL_Path, Wide_DLL_Path_Size, Bytes_Written);

    if(*Bytes_Written == 0){
        error("Inject_DLL: Failed to write memory in target process for %s. \n Error code: 0x%lX", filename, GetLastError());
        CloseHandle(hKernel);
        return;
    }

    HANDLE hThread{CreateRemoteThread(hProcess, NULL, 0, LoadLib, rBuffer, 0, *ThreadID)};

    if(hThread == NULL){
        error("Inject_DLL: Failed to create remote thread in target process for %s. \n Error code: 0x%lX", filename, GetLastError());
        CloseHandle(hKernel);
        return;
    }

    return hThread;
}

wchar_t * str_to_wchar_t(std::string src){
    std::wstring Src_Buffer{};
    Src_Buffer.assign(src.begin(), src.end());
    return Src_Buffer.data();
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


