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
namespace fs = std::filesystem;

enum states {off, once, leave};

HANDLE GetProcHandle(DWORD PID = NULL); 
std::vector<fs::path> Get_DLLs();
HANDLE Inject_DLL(const HANDLE hProcess, const fs::path DLL_Path, LPVOID* rBuffer);
HANDLE ValidateProcHandle(DWORD PID);
wchar_t * str_to_wchar_t(std::string src);
bool Free_DLL(const HANDLE hProcess, LPVOID rBuffer, HMODULE hModule, fs::path filename);

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
        try{
            if(stoi(input) <= filepaths_size){
                int choice = stoi(input)-1;
                switch (state[choice]){
                case off:
                    state[choice] = once;
                    break;
                case once:
                    state[choice] = leave;
                    break;
                case leave:
                    state[choice] = off;
                    break;
                }
            }
        }
        catch(std::invalid_argument){
            if(input == "r" || input == "run"){
                break;
            }
            else if(input == "q" || input == "quit" || input == "exit"){
                return 0;
            }
            else if(input == "rescan"){
                filepaths = Get_DLLs();
                filepaths_size = filepaths.size();
                
                filenames.clear();
                for(const auto &x : filepaths){
                    filenames.push_back(x.filename().string());
                }

                state.clear();
                for(size_t x{}; x<filepaths_size; x++){
                    state.push_back(off);
                }
            }
            else{
                warn("Incorrect input given, please provide a correct input. if you have given a correct input, please open a new issue.");
                info("Controls: [q/quit/exit - quit program; r/run - inject DLL(s); rescan - rescan directory for DLLs]");
            }

        }
        catch(std::out_of_range){
            error("stoi has thrown an std::out_of_range exception! Exiting...");
            return 1;
        }
    }while(true);

    std::map<size_t, std::pair<fs::path, states>> Active_Filepaths{};

    for(size_t x{}; x<filepaths_size; x++){
        if(state[x] == off){
            continue;
        }

        Active_Filepaths.insert( {Active_Filepaths.size(), {filepaths[x], state[x]} } );
    }

    std::vector<LPVOID> Memory_Pages{};
    std::vector<HANDLE> Thread_Handles{};


    for(const auto x : Active_Filepaths){
        LPVOID *Memory_Page{ new LPVOID };
        HANDLE Thread_Handle{};

        Thread_Handle = Inject_DLL(hProcess, x.second.first, Memory_Page);
        info("0x%lX", Thread_Handle);
        if(Thread_Handle == NULL){
            continue;
        }
        
        Memory_Pages.push_back(*Memory_Page);
        Thread_Handles.push_back(Thread_Handle);
        delete Memory_Page;
    }

    std::vector<HANDLE> To_DeAllocate{};

    size_t PLACEHOLDER_NAME{};
    for(const auto x : Active_Filepaths){
        switch(x.second.second){
            case once:
                To_DeAllocate.push_back(Thread_Handles[PLACEHOLDER_NAME]);
                PLACEHOLDER_NAME++;
                break;
            case leave:
                PLACEHOLDER_NAME++;
                break;
                
        }

    }
    WaitForMultipleObjects(To_DeAllocate.size(), To_DeAllocate.data(), true, INFINITE);
    
    std::cout << "Memory Pages: ";
    for(const auto x : Memory_Pages){
        std::cout << x << ", ";
    }
    std::cout << "\n";
    std::cout << "Thread Handles: ";
    for(const auto x : Thread_Handles){
        std::cout << x << ", ";
    }
    std::cout << "\n";

    info("Threads have completed execution!");
    for(auto x : Active_Filepaths){
        if(x.second.second != once){
            continue;
        }
        std::cout << Memory_Pages[x.first] << "\n";
        HMODULE *ExitCode{ new HMODULE};
        GetExitCodeThread(Thread_Handles[x.first], (LPDWORD)ExitCode);
        info("Module Handle: %llX", *ExitCode);
        Free_DLL(hProcess, Memory_Pages[x.first], *ExitCode, x.second.first.filename());
        CloseHandle(Thread_Handles[x.first]);
        Thread_Handles.erase(Thread_Handles.begin()+x.first);
        Memory_Pages.erase(Memory_Pages.begin()+x.first);
        delete ExitCode;
    }


    CloseHandle(hProcess);
    return 0;
}


/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

HANDLE Inject_DLL(const HANDLE hProcess, const fs::path DLL_Path, LPVOID* rBuffer){
    std::string filename{DLL_Path.filename().string()};
    
    info("Now attempting injection of %s into the target process", filename.data());    
    HMODULE hKernel{GetModuleHandleW(L"Kernel32")}; // Get module handle for Kernel32.dll

    if(hKernel == NULL){ // Check if acquired handle for Kernel32.dll
        error("Inject_DLL: Failed to acquire Kernel32.dll handle for %s. \n Error code: 0x%lX", filename, GetLastError());
        return NULL;
    }
    LPTHREAD_START_ROUTINE LoadLib{(LPTHREAD_START_ROUTINE) GetProcAddress(hKernel, "LoadLibraryW")}; // Thread routine

    wchar_t Wide_DLL_Path[MAX_PATH]{}; // Wide string path to the DLL
    wcscpy(Wide_DLL_Path, str_to_wchar_t(DLL_Path.string())); // Copy string path into wchar array
                                                                
    size_t Wide_DLL_Path_Size{sizeof(Wide_DLL_Path)}; // Size of the Path (since the max is 260 chars, thats how big itll be)

    *rBuffer = VirtualAllocEx(hProcess, NULL, Wide_DLL_Path_Size, (MEM_COMMIT | MEM_RESERVE), PAGE_EXECUTE_READWRITE);

    if(*rBuffer == NULL){
        error("Inject_DLL: Failed to allocate memory in target process for %s. \n Error code: 0x%lX", filename, GetLastError());
        CloseHandle(hKernel);
        return NULL;
    }
    info("Successfully allocated memory in target process!");    
    
    size_t* Bytes_Written{ new size_t };

    WriteProcessMemory(hProcess, *rBuffer, Wide_DLL_Path, Wide_DLL_Path_Size, Bytes_Written);

    if(*Bytes_Written == 0){
        error("Inject_DLL: Failed to write memory in target process for %s. \n Error code: 0x%lX", filename, GetLastError());
        CloseHandle(hKernel);
        delete Bytes_Written;
        return NULL;
    }

    info("Successfully written to memory in target process!");    
    HANDLE hThread{CreateRemoteThread(hProcess, NULL, 0, LoadLib, *rBuffer, 0, NULL)};

    if(hThread == NULL){
        error("Inject_DLL: Failed to create remote thread in target process for %s. \n Error code: 0x%lX", filename, GetLastError());
        CloseHandle(hKernel);
        delete Bytes_Written;
        return NULL;
    }
    info("Successfully created remote thread in target process! \n");    
    CloseHandle(hKernel);
    delete Bytes_Written;

    return hThread;
}

/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

bool Free_DLL(const HANDLE hProcess, LPVOID rBuffer, HMODULE hModule, fs::path filepath){
    std::string filename{filepath.filename().string()};

    info("Starting Deallocation of %s", filename.data());
    HMODULE hKernel{GetModuleHandleW(L"Kernel32")}; // Get module handle for Kernel32.dll

    if(hKernel == NULL){ // Check if acquired handle for Kernel32.dll
        error("Inject_DLL: Failed to acquire Kernel32.dll handle for . \n Error code: 0x%lX", GetLastError());
        CloseHandle(hKernel);
        return false;
    }

    LPDWORD ExitCode{ new DWORD };
    size_t Bytes{};

    if(WriteProcessMemory(hProcess, rBuffer, &hModule, sizeof(DWORD), &Bytes) == 0){
        error("cant write handle :( Error: %lX", GetLastError());
    }
    info("Bytes written: %lld", Bytes);

    LPTHREAD_START_ROUTINE FreeLib{(LPTHREAD_START_ROUTINE) GetProcAddress(hKernel, "FreeLibrary")}; // Thread routine
    HANDLE hThread{CreateRemoteThread(hProcess, NULL, 0, FreeLib, rBuffer, 0, NULL)};

    WaitForSingleObject(hThread, INFINITE);

    GetExitCodeThread(hThread, ExitCode);

    if(*ExitCode == 0){
        warn("Could not free library %s. Error code: %lX", filename.data(), GetLastError());
        delete ExitCode;
        CloseHandle(hKernel);
        CloseHandle(hThread);
        return false;
    }


    info("%s has been freed successfully!", filename.data());

    CloseHandle(hKernel);
    CloseHandle(hThread);
    
    // if(VirtualFreeEx(hProcess, rBuffer, 0, MEM_RELEASE) == 0){
    //     warn("Could not deallocate memory for address space 0x%lX. Error code: 0x%lX", rBuffer, GetLastError());
    //     delete ExitCode;
    //     CloseHandle(hKernel);
    //     CloseHandle(hThread);
    //     return false;
    // }
    delete ExitCode;
    info("Deallocated %s's memory page successfully!\n", filename.data());

    return true;
    
}

/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

wchar_t * str_to_wchar_t(std::string src){
    std::wstring Src_Buffer{};
    Src_Buffer.assign(src.begin(), src.end());
    return Src_Buffer.data();
}

/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

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

/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

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
    okay("Acquired process handle! 0x%lX", hProcess);
    return hProcess;
}

/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

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


