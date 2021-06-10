#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <stdio.h>
#include <winternl.h>
#include <stdlib.h>

/*  TODO
 *  Load file from disk
 *  Parse Dll
 *  Compare each function to the disk version
 */

#define DEREF_32( name )*(DWORD *)(name)
#define DEREF_16( name )*(WORD *)(name)

 // Ignore "x differs in parameter lists from y"
#pragma warning( disable : 4113 )
// Ignore "x differs in levels of indirection from y"
#pragma warning( disable : 4047 )

int nHooked = 0;
int nClean = 0;



/*   Find the address of a loaded module   */
UINT_PTR FindDLLByName(wchar_t* searchDLL, BOOLEAN verbose) {

    PPEB Peb = NULL;
    PPEB_LDR_DATA Loader = NULL;
    PLIST_ENTRY Head = NULL;
    PLIST_ENTRY Current = NULL;

    // Get PEB address from GS:0x60 register

    Peb = (PPEB)__readgsqword(0x60);

    // PPEB_LDR_DATA contains information about the loaded modules for the process
    Loader = (PPEB_LDR_DATA)(PBYTE)Peb->Ldr;

    // The head of a doubly-linked list that contains the loaded modules for the process
    Head = &Loader->InMemoryOrderModuleList;

    Current = Head->Flink;

    do {
        // Retrieve address of InMemoryOrderLinks from Current, casted to PLDR_DATA_TABLE_ENTRY, using CONTAINING_RECORD macro
        PLDR_DATA_TABLE_ENTRY dllEntry = CONTAINING_RECORD(Current, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);

        // Get the full DLL path as Unicode string
        wchar_t* dllName = (wchar_t*)dllEntry->FullDllName.Buffer;

        // Get the module base address
        UINT_PTR dllAddress = (UINT_PTR)dllEntry->DllBase;

        // Check if current DLL matches search DLL
        wchar_t* result = wcsstr(dllName, searchDLL);
        if (verbose) {
            printf("[*] %ws\n", dllName);
        }
        if (result != NULL)
        {
            return dllAddress;
        }

        // Move to the next module
        Current = Current->Flink;
    } while (Current != Head);
    printf("[!] Failed to find %ws!\n", searchDLL);

    return 0;
}

/*   Find the address of an exported function   */
// https://gist.dreamtobe.cn/slaeryan/691b2d6e7ab241f53f7f3b25aca30eaf
FARPROC FindProcAddress(UINT_PTR uiLibraryAddress, LPCSTR lpProcName) {
    FARPROC fpResult = NULL;

    if (uiLibraryAddress == (UINT_PTR)NULL)
        return NULL;

    UINT_PTR uiAddressArray = 0;
    UINT_PTR uiNameArray = 0;
    UINT_PTR uiNameOrdinals = 0;
    PIMAGE_NT_HEADERS pNtHeaders = NULL;
    PIMAGE_DATA_DIRECTORY pDataDirectory = NULL;
    PIMAGE_EXPORT_DIRECTORY pExportDirectory = NULL;

    // get the address of the modules NT Header
    pNtHeaders = (PIMAGE_NT_HEADERS)(uiLibraryAddress + ((PIMAGE_DOS_HEADER)uiLibraryAddress)->e_lfanew);

    pDataDirectory = (PIMAGE_DATA_DIRECTORY)&pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];

    // get the address of the export directory
    pExportDirectory = (PIMAGE_EXPORT_DIRECTORY)(uiLibraryAddress + pDataDirectory->VirtualAddress);

    // get the VA for the array of addresses
    uiAddressArray = (uiLibraryAddress + pExportDirectory->AddressOfFunctions);

    // get the RVA for the array of name pointers
    uiNameArray = (uiLibraryAddress + pExportDirectory->AddressOfNames);

    // get the RVA for the array of name ordinals
    uiNameOrdinals = (uiLibraryAddress + pExportDirectory->AddressOfNameOrdinals);

    // test if we are importing by name or by ordinal...
    if (((DWORDLONG)lpProcName & 0xFFFF0000) == 0x00000000)
    {
        // use the import ordinal (- export ordinal base) as an index into the array of addresses
        uiAddressArray += ((IMAGE_ORDINAL((DWORDLONG)lpProcName) - pExportDirectory->Base) * sizeof(DWORD));

        // resolve the address for this imported function
        fpResult = (FARPROC)(uiLibraryAddress + DEREF_32(uiAddressArray));
    }
    else
    {
        // Iterate over number of function names
        DWORD dwCounter = pExportDirectory->NumberOfNames;
        while (dwCounter--)
        {
            // Get the function name
            char* cpExportedFunctionName = (char*)(uiLibraryAddress + DEREF_32(uiNameArray));

            // test if we have a match
            if (strcmp(cpExportedFunctionName, lpProcName) == 0)
            {
                // use the function's ordinal value as an index into the array of name pointers
                uiAddressArray += (DEREF_16(uiNameOrdinals) * sizeof(DWORD));

                // calculate the actual address for the function (DLL base address + function RVA)
                fpResult = (FARPROC)(uiLibraryAddress + DEREF_32(uiAddressArray));

                break;
            }

            // get the next exported function name, using pointer addition
            uiNameArray += sizeof(DWORD);

            // get the next exported function name ordinal, using pointer addition
            uiNameOrdinals += sizeof(WORD);
        }
    }

    if (fpResult == NULL)
        printf("[!] Failed to find %s!\n", lpProcName);
    return fpResult;
}

void ListFunctionAddresses(UINT_PTR pLibraryAddress, char* szDllName, BOOLEAN verbose) {

    /*  Make sure the DLL address is not null  */
    if (pLibraryAddress == (UINT_PTR)NULL)
    {
        printf("[*] DLL address is null!\n");
        return;
    }

    UINT_PTR uiAddressArray = 0;
    UINT_PTR uiNameArray = 0;
    UINT_PTR uiNameOrdinals = 0;
    PIMAGE_NT_HEADERS pNtHeaders = NULL;
    PIMAGE_DATA_DIRECTORY pDataDirectory = NULL;
    PIMAGE_EXPORT_DIRECTORY pExportDirectory = NULL;
    const unsigned char correct_bytes[4] = { 0x4c, 0x8B, 0xD1, 0xB8 };
    unsigned char assemblyBytes[25];
    unsigned int hash = 0;

    HANDLE hDll = GetModuleHandleA(szDllName);

    /*  Get the address of the modules NT Header  */
    pNtHeaders = (PIMAGE_NT_HEADERS)(pLibraryAddress + ((PIMAGE_DOS_HEADER)pLibraryAddress)->e_lfanew);

    pDataDirectory = (PIMAGE_DATA_DIRECTORY)&pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];

    /*  Get the address of the export directory  */
    pExportDirectory = (PIMAGE_EXPORT_DIRECTORY)(pLibraryAddress + pDataDirectory->VirtualAddress);

    /*  Get the VA for the array of addresses  */
    uiAddressArray = (pLibraryAddress + pExportDirectory->AddressOfFunctions);

    /*  Get the RVA for the array of name pointers  */
    uiNameArray = (pLibraryAddress + pExportDirectory->AddressOfNames);

    /*  Get the RVA for the array of name ordinals  */
    uiNameOrdinals = (pLibraryAddress + pExportDirectory->AddressOfNameOrdinals);

    /*  Iterate over the number of function names  */
    DWORD dwCounter = pExportDirectory->NumberOfNames;
    while (dwCounter--)
    {
        /*  Get the function name  */
        char* szExportedFunctionName = (char*)(pLibraryAddress + DEREF_32(uiNameArray));
        // printf( "\t[*] Function name: %s\n", szExportedFunctionName );

        char* pProcAddress = (char*)GetProcAddress((HMODULE)hDll, szExportedFunctionName);
        // printf( "\t[*] Function address: 0x%p\n", pProcAddress );

        /*  Get the first 4 assembly bytes for comparison  */
        if (pProcAddress != NULL)
        {
            for (int i = 0; i < 25; i++)
            {
                assemblyBytes[i] = pProcAddress[i];
            }
        }
        else
            continue;

        /*  Check if function is Nt*  */
        if (szExportedFunctionName[0] == 'N' && szExportedFunctionName[1] == 't')
        {


            if (correct_bytes[0] == int(assemblyBytes[0]) && correct_bytes[1] == int(assemblyBytes[1]) && correct_bytes[2] == int(assemblyBytes[2]) && correct_bytes[3] == int(assemblyBytes[3]))
            {
                if (verbose) {
                    printf("\t[-]%s has NOT been hooked!\n", szExportedFunctionName);
                }
                nClean++;
            }
            else
            {
                printf("\t[+] %s HAS been hooked!\n", szExportedFunctionName);
                printf("\t\t");
                if (verbose) {
                    for (int i = 0; i < 25; i++)
                    {
                        printf("%02hhX ", pProcAddress[i]);
                    }
                    printf("\n");
                }
                nHooked++;
            }

        }
        /*  Check if function is Zw*  */
        else if (szExportedFunctionName[0] == 'Z' && szExportedFunctionName[1] == 'w')
        {

            

            if (correct_bytes[0] == int(assemblyBytes[0]) && correct_bytes[1] == int(assemblyBytes[1]) && correct_bytes[2] == int(assemblyBytes[2]) && correct_bytes[3] == int(assemblyBytes[3]))
            {
                if (verbose) {
                    printf("\t[-]%s has NOT been hooked!\n", szExportedFunctionName);
                }
                nClean++;
            }
            else
            {
                printf("\t[+] %s HAS been hooked!\n", szExportedFunctionName);
                printf("\t\t");
                if (verbose) {
                    for (int i = 0; i < 25; i++)
                    {
                        printf("%02hhX ", pProcAddress[i]);
                    }
                    printf("\n");
                }
                nHooked++;
            }
        }
        /*  Deal with Win32 APIs  */
        else
        {
            //UNCOMMENT THE FIRST TWO PRINTF STATEMENTS IF YOU WANT TO DISPLAY WIN32 API NAMES 
            //printf("\t[*] %s\n", szExportedFunctionName);
            //printf("\t\t");
            //for (int i = 0; i < 25; i++)
            //{
              //  printf("%02hhX ", pProcAddress[i]);
            //}
            //printf("\n");
        }

        /*  Get the next exported function name, using pointer addition  */
        uiNameArray += sizeof(DWORD);

        /*  Get the next exported function name ordinal, using pointer addition  */
        uiNameOrdinals += sizeof(WORD);
    }
}

void ListFunctionAddresses2(UINT_PTR pLibraryAddress, char* szDllName, BOOLEAN verbose) {

    /*  Make sure the DLL address is not null  */
    if (pLibraryAddress == (UINT_PTR)NULL)
    {
        printf("[*] DLL address is null!\n");
        return;
    }

    UINT_PTR uiAddressArray = 0;
    UINT_PTR uiNameArray = 0;
    UINT_PTR uiNameOrdinals = 0;
    PIMAGE_NT_HEADERS pNtHeaders = NULL;
    PIMAGE_DATA_DIRECTORY pDataDirectory = NULL;
    PIMAGE_EXPORT_DIRECTORY pExportDirectory = NULL;
    const unsigned char correct_bytes[4] = { 0x4c, 0x8B, 0xD1, 0xB8 };
    unsigned char assemblyBytes[25];
    unsigned int hash = 0;

    HANDLE hDll = GetModuleHandleA(szDllName);

    /*  Get the address of the modules NT Header  */
    pNtHeaders = (PIMAGE_NT_HEADERS)(pLibraryAddress + ((PIMAGE_DOS_HEADER)pLibraryAddress)->e_lfanew);

    pDataDirectory = (PIMAGE_DATA_DIRECTORY)&pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];

    /*  Get the address of the export directory  */
    pExportDirectory = (PIMAGE_EXPORT_DIRECTORY)(pLibraryAddress + pDataDirectory->VirtualAddress);

    /*  Get the VA for the array of addresses  */
    uiAddressArray = (pLibraryAddress + pExportDirectory->AddressOfFunctions);

    /*  Get the RVA for the array of name pointers  */
    uiNameArray = (pLibraryAddress + pExportDirectory->AddressOfNames);

    /*  Get the RVA for the array of name ordinals  */
    uiNameOrdinals = (pLibraryAddress + pExportDirectory->AddressOfNameOrdinals);

    /*  Iterate over the number of function names  */
    DWORD dwCounter = pExportDirectory->NumberOfNames;
    while (dwCounter--)
    {
        /*  Get the function name  */
        char* szExportedFunctionName = (char*)(pLibraryAddress + DEREF_32(uiNameArray));
        // printf( "\t[*] Function name: %s\n", szExportedFunctionName );

        char* pProcAddress = (char*)GetProcAddress((HMODULE)hDll, szExportedFunctionName);
        // printf( "\t[*] Function address: 0x%p\n", pProcAddress );

        /*  Get the first 4 assembly bytes for comparison  */
        if (pProcAddress != NULL)
        {
            for (int i = 0; i < 25; i++)
            {
                assemblyBytes[i] = pProcAddress[i];
            }
        }
        else
            continue;

        /*  Check if function is Nt*  */
        if (szExportedFunctionName[0] == 'N' && szExportedFunctionName[1] == 't')
        {
            if (correct_bytes[0] == assemblyBytes[0] && correct_bytes[1] == assemblyBytes[1] && correct_bytes[2] == assemblyBytes[2] && correct_bytes[3] == assemblyBytes[3])
            {
                if (verbose) {
                    printf("\t[-]%s has NOT been hooked!\n", szExportedFunctionName);
                }
                nClean++;
            }
            else
            {
            printf("\t[+] %s HAS been hooked!\n", szExportedFunctionName);
            printf("\t\t");
            for (int i = 0; i < 25; i++)
            {
                printf("%02hhX ", pProcAddress[i]);
            }
            printf("\n");
            nHooked++;
            }

        }
        /*  Check if function is Zw*  */
        else if (szExportedFunctionName[0] == 'Z' && szExportedFunctionName[1] == 'w')
        {
        if (correct_bytes[0] == assemblyBytes[0] && correct_bytes[1] == assemblyBytes[1] && correct_bytes[2] == assemblyBytes[2] && correct_bytes[3] == assemblyBytes[3])
        {
            if (verbose) {
                printf("\t[-]%s has NOT been hooked!\n", szExportedFunctionName);
            }
            nClean++;
        }
        else
        {
            printf("\t[+] %s HAS been hooked!\n", szExportedFunctionName);
            printf("\t\t");
            for (int i = 0; i < 25; i++)
            {
                printf("%02hhX ", pProcAddress[i]);
            }
            printf("\n");
            nHooked++;
        }
        }
        /*  Deal with Win32 APIs  */
        else
        {
        printf("\t[*] %s\n", szExportedFunctionName);
        printf("\t\t");
        for (int i = 0; i < 25; i++)
        {
            printf("%02hhX ", pProcAddress[i]);
        }
        printf("\n");
        }

        /*  Get the next exported function name, using pointer addition  */
        uiNameArray += sizeof(DWORD);

        /*  Get the next exported function name ordinal, using pointer addition  */
        uiNameOrdinals += sizeof(WORD);
    }
}

LPVOID MapDLL(char* szDllPath)
{
    /*  Load DLL from disk  */
    HANDLE hFileHandle = INVALID_HANDLE_VALUE;
    __try
    {
        hFileHandle = CreateFileA(szDllPath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        printf("[*] Failed to open %s!\n", szDllPath);
        exit(EXIT_FAILURE);
    }

    /*  Create file mapping of DLL  */
    HANDLE hFileMapping = INVALID_HANDLE_VALUE;
    __try
    {
        hFileMapping = CreateFileMapping(hFileHandle, NULL, PAGE_READONLY | SEC_IMAGE, 0, 0, NULL);
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        printf("[*] Failed to create file mapping\n");
        exit(EXIT_FAILURE);
    }

    /*  Map view of DLL  */
    LPVOID lpAddress = NULL;
    __try
    {
        lpAddress = MapViewOfFile(hFileMapping, FILE_MAP_READ, 0, 0, 0);
        return lpAddress;
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        printf("[*] Failed to map view of %s\n", szDllPath);
        exit(EXIT_FAILURE);
    }

}

int main(int argc, char** argv)
{
    BOOLEAN verbose = false;
    BOOLEAN unhook = false;
    for (int i = 1; i < argc; ++i){
        if ((strcmp(argv[i], "-help") == 0) || (strcmp(argv[i], "-h")) == 0) {
            printf("\nUsage : %s <options>\n\nOptions :\n -d or -debug\t: to show unhooked functions also\n -u or -unhook\t: to load shellycoat_x64.dll unhooker (https://github.com/slaeryan/AQUARMOURY/) \n -h or -help\t: to show this message\n",argv[0]);
            exit(0);
        }
        else if ((strcmp(argv[i], "-d") == 0) || (strcmp(argv[i], "-debug")) == 0) {
            verbose = true;
        } else if ((strcmp(argv[i], "-u") == 0) || (strcmp(argv[i], "-unhook")) == 0) {
            unhook = true;
        }
        else {
            printf("Unrecognized option\nUsage : %s -h for usage\n",argv[0]);
            exit(1);
            return 1;
        }

    }

    if (unhook) {
        HINSTANCE hinstLib = LoadLibrary(TEXT("shellycoat_x64.dll"));
        if (hinstLib != NULL) {
            printf("[*] Loaded shellycoat_x64.dll to Unhook \n");
        }
        else {
            printf("[*] Error no shellycoat_x64.dll found !\n");
            exit(1);
        }
    }
    printf("[*] ntdll.dll\n");
    // LPVOID pMappedDllAddress = MapDLL( "c:\\windows\\system32\\kernel32.dll" );
    LPVOID pMappedDllAddress = MapDLL((char*)"c:\\windows\\system32\\ntdll.dll");
    printf("[*] pMappedDllAddress 0x%p\n", pMappedDllAddress);

    LPVOID pLocalDllAddress = (LPVOID)FindDLLByName((wchar_t*)L"ntdll.dll", (BOOLEAN)verbose);
    printf("[*] pLocalDllAddress  0x%p\n", pLocalDllAddress);

    // ListFunctionAddresses( pLocalDllAddress, "ntdll.dll" );
    ListFunctionAddresses((UINT_PTR)pMappedDllAddress, (char*)"ntdll.dll", (BOOLEAN)verbose);

    printf("[*] %d hooked functions found.\n", nHooked);
    printf("[*] %d clean functions found.\n", nClean);


    // Sleep(10000);
    return 0;
}
