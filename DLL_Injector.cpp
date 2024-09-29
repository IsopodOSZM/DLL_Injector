#include <iostream>
#include <fstream>
#include <windows.h>
#include <filesystem>
#include <vector>
#include <math.h>

#define okay(msg, ...) printf("[+] " msg " \n",##__VA_ARGS__)
#define info(msg, ...) printf("[*] " msg " \n",##__VA_ARGS__)
#define warn(msg, ...) printf("[!] " msg " \n",##__VA_ARGS__)
namespace fs = std::filesystem;

HANDLE GetProcHandle();
std::vector<fs::path> ListDlls();

int main(int argc, char *argv[]){
    int active_amount{}, handlePindex{}, choice{}; // How many DLLs are active; used to assign thread handles to the correct places; which DLL has been chosen (formatted user input)

    HMODULE hKernel{}; // Handle of the Kernel32.dll module
    HANDLE hprocess{}; // Handle of target process

    hprocess = GetProcHandle(); // Handle the acquisition of target process handle
    hKernel = GetModuleHandleW(L"Kernel32"); // Get module handle for Kernel32.dll
    if(!hKernel){
        CloseHandle(hprocess);
        CloseHandle(hKernel);
        warn("Failed to get Kernel32.dll handle. Error code: 0x%lx", GetLastError());
        exit(1);
    }
    LPTHREAD_START_ROUTINE LoadLib{(LPTHREAD_START_ROUTINE) GetProcAddress(hKernel, "LoadLibraryW")}; // Thread routine

    char input[5]; // Raw user input 

    std::vector<fs::path> filepaths{ListDlls()}; // Filepaths of all DLLs
    size_t filesize{filepaths.size()}; // How many DLLs have been found

    std::vector<std::string> files{}; // DLL names
    for(size_t x{0}; x<filesize; x++){
        files.push_back(filepaths[x].filename().string()); // add the names to the files vector
    }

    bool *activated{(bool*)malloc(sizeof(bool)*files.size())}; // bool pointer which tells which DLLs are active and which are not
    for(size_t x{0}; x<filesize; x++){
        activated[x] = false; // initialize all the values to false (idk why its not done automatically)
    }

    info("Found the following DLL files. Please input number to toggle: ");

    do{
        for(size_t x = 0; x<filesize; x++){ // Print all found DLLs and the activated label if they are active.
            if(activated[x] == true){
                std::cout << (x+1) << ". " << files[x] << " (Activated)" <<std::endl;
            }
            else{
                std::cout << (x+1) << ". " << files[x] << std::endl;
            }
        }
        
        std::cin >> input; // Get User choice
        std::cout << std::endl;
        if(strcmp(input, "exit")==0){ // Exit program and clean up handle
            CloseHandle(hprocess);
            CloseHandle(hKernel);
            exit(1);
        }
        if(strcmp(input, "r")==0){ // Rescan DLLs
            filepaths = ListDlls();
            continue;
        }
        if(strcmp(input, "run")==0){ // Inject activated DLLs into process
            break;
        }
        if(atoi(input) == 0 && input[0] != 0){ // Invalid Input
            warn("Invalid input, please provide a valid input. [Valid input: number corresponding to DLL; r - rescan DLLs; exit - exit program; run - inject activated DLLs]");
            continue;
        }
        choice = abs(abs(atoi(input))-1)%filesize; // Handles User Input for what DLL has been picked
        switch (activated[choice]){ // Toggles activation state of a DLL
        case true:
            activated[choice] = false;
            active_amount--;
            break;
        case false:
            activated[choice] = true;
            active_amount++;
            break;
        }

    }while(true);

    std::vector<HANDLE> hThreadIDs{};

    for(size_t x = 0; x<filesize; x++){

        if(activated[x]==false){ // Checks if the DLL is activated
            continue;
        }
        std::string filepathbuffer{filepaths[x].string()};
        std::wstring filepathbufferWideString{};
        filepathbufferWideString.assign(filepathbuffer.begin(), filepathbuffer.end());
        wchar_t filepath[MAX_PATH]{};
        wcscpy(filepath, filepathbufferWideString.data());
        size_t filepath_size{wcslen(filepath)*2+2}; //process the filename to widestring
        

        LPVOID rBuffer{}; // Address of the allocated memory where the filepath is stored
        rBuffer = VirtualAllocEx(hprocess, NULL, filepath_size, (MEM_COMMIT | MEM_RESERVE), PAGE_EXECUTE_READWRITE); // Allocates memory in target process

        if(!rBuffer){
            warn("Failed to Allocate memory in target process. Continuing to next DLL. Error code: 0x%lx", GetLastError());
            continue;
        }
        okay("Successfully allocated memory in target process!");
        WriteProcessMemory(hprocess, rBuffer, filepath, filepath_size, NULL); // Writes DLL filepath to allocated memory
        LPDWORD Threadid{}; // ID of thread
        hThreadIDs.push_back(CreateRemoteThread(hprocess, NULL, 0, LoadLib, rBuffer, 0, Threadid)); // creates a thread which loads activated DLLs
        if(!hThreadIDs[handlePindex]){
            warn("Failed to create remote thread for %s. Error code: 0x%lx", files[x], GetLastError());
            info("Continuing execution");
        }else{
            okay("Successfully created thread in target process!");
        }
        info("Written to: 0x%llX", rBuffer);
        info("Errors?: 0x%llX", GetLastError());
    }
    info("Waiting for Threads to finish execution!");
    WaitForMultipleObjects(active_amount, &(hThreadIDs.data()[0]), true, INFINITE); // Waits for threads
    info("Threads finished execution! Cleaning up...");




    delete[] activated; // deallocates memory from activated
    for(size_t x{}; x<(handlePindex+1);x++){
        CloseHandle(hThreadIDs[x]);
    }
    CloseHandle(hprocess); // CLEANUP
    CloseHandle(hKernel);
    okay("Cleanup finished. Exiting... Goodbye! :3");
    return 0;
}

HANDLE GetProcHandle(){
    
    DWORD PID{0};
    HANDLE hProcess{0};

    std::cout << "Please Insert a PID (Program ID) of the program you want to inject: ";
    std::cin >> PID;
    if(PID%4 != 0 || PID == 0){
        warn("Invalid PID Given");
        exit(EXIT_FAILURE);
    }

    hProcess = OpenProcess(PROCESS_ALL_ACCESS, false, PID);

    if(hProcess == NULL){
        warn("Failed to acquire handle. Error Code: 0x%lx", GetLastError());
        CloseHandle(hProcess);
    }
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


