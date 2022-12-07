#include "syscalls_mem.h"



CRACK_SYSCALL_LIST CRACK_Syscall_List;

DWORD CRACK_Hash_Sys_call(PCSTR FunctionName)
{
    DWORD i = 0;
    DWORD Hash = CRACK_SEED;

    while (FunctionName[i])
    {
        WORD PartialName = *(WORD*)((ULONG64)FunctionName + i++);
        Hash ^= PartialName + CRACK_ROR8(Hash);
    }

    return Hash;
}

BOOL CRACK_Populate_Syscall_List(void)
{
    // Return early if the list is already populated.
    if (CRACK_Syscall_List.Count) return TRUE;

#if defined(_WIN64)
    PCRACK_PEB Peb = (PCRACK_PEB)__readgsqword(0x60);
#else
    PCRACK_PEB Peb = (PCRACK_PEB)__readfsdword(0x30);
#endif
    PCRACK_PEB_LDR_DATA Ldr = Peb->Ldr;
    PIMAGE_EXPORT_DIRECTORY ExportDirectory = NULL;
    PVOID DllBase = NULL;

   
    PCRACK_LDR_DATA_TABLE_ENTRY LdrEntry;
    for (LdrEntry = (PCRACK_LDR_DATA_TABLE_ENTRY)Ldr->Reserved2[1]; LdrEntry->DllBase != NULL; LdrEntry = (PCRACK_LDR_DATA_TABLE_ENTRY)LdrEntry->Reserved1[0])
    {
        DllBase = LdrEntry->DllBase;
        PIMAGE_DOS_HEADER DosHeader = (PIMAGE_DOS_HEADER)DllBase;
        PIMAGE_NT_HEADERS NtHeaders = CRACK_RVA2VA(PIMAGE_NT_HEADERS, DllBase, DosHeader->e_lfanew);
        PIMAGE_DATA_DIRECTORY DataDirectory = (PIMAGE_DATA_DIRECTORY)NtHeaders->OptionalHeader.DataDirectory;
        DWORD VirtualAddress = DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
        if (VirtualAddress == 0) continue;

        ExportDirectory = (PIMAGE_EXPORT_DIRECTORY)CRACK_RVA2VA(ULONG_PTR, DllBase, VirtualAddress);

        // If this is NTDLL.dll, exit loop.
        PCHAR DllName = CRACK_RVA2VA(PCHAR, DllBase, ExportDirectory->Name);

        if ((*(ULONG*)DllName | 0x20202020) != 'ldtn') continue;
        if ((*(ULONG*)(DllName + 4) | 0x20202020) == 'ld.l') break;
    }

    if (!ExportDirectory) return FALSE;

    DWORD NumberOfNames = ExportDirectory->NumberOfNames;
    PDWORD Functions = CRACK_RVA2VA(PDWORD, DllBase, ExportDirectory->AddressOfFunctions);
    PDWORD Names = CRACK_RVA2VA(PDWORD, DllBase, ExportDirectory->AddressOfNames);
    PWORD Ordinals = CRACK_RVA2VA(PWORD, DllBase, ExportDirectory->AddressOfNameOrdinals);

    
    DWORD i = 0;
    PCRACK_SYSCALL_ENTRY Entries = CRACK_Syscall_List.Entries;
    do
    {
        PCHAR FunctionName = CRACK_RVA2VA(PCHAR, DllBase, Names[NumberOfNames - 1]);

        
        if (*(USHORT*)FunctionName == 'wZ')
        {
            Entries[i].Hash = CRACK_Hash_Sys_call(FunctionName);
            Entries[i].Address = Functions[Ordinals[NumberOfNames - 1]];

            i++;
            if (i == CRACK_MAX_ENTRIES) break;
        }
    } while (--NumberOfNames);

    
    CRACK_Syscall_List.Count = i;

    
    for (i = 0; i < CRACK_Syscall_List.Count - 1; i++)
    {
        for (DWORD j = 0; j < CRACK_Syscall_List.Count - i - 1; j++)
        {
            if (Entries[j].Address > Entries[j + 1].Address)
            {
                
                CRACK_SYSCALL_ENTRY TempEntry;

                TempEntry.Hash = Entries[j].Hash;
                TempEntry.Address = Entries[j].Address;

                Entries[j].Hash = Entries[j + 1].Hash;
                Entries[j].Address = Entries[j + 1].Address;

                Entries[j + 1].Hash = TempEntry.Hash;
                Entries[j + 1].Address = TempEntry.Address;
            }
        }
    }

    return TRUE;
}

EXTERN_C DWORD CRACK_SNumber(DWORD CRACK_H)
{
    
    if (!CRACK_Populate_Syscall_List()) return -1;

    for (DWORD i = 0; i < CRACK_Syscall_List.Count; i++)
    {
        if (CRACK_H == CRACK_Syscall_List.Entries[i].Hash)
        {
            return i;
        }
    }

    return -1;
}

EXTERN_C DWORD CRACK_Get_Base_N(DWORD CRACK_H)

{

#if defined(_WIN64)
    PCRACK_PEB Peb = (PCRACK_PEB)__readgsqword(0x60);
#else
    PCRACK_PEB Peb = (PCRACK_PEB)__readfsdword(0x30);
#endif
    PCRACK_PEB_LDR_DATA Ldr = Peb->Ldr;
    PIMAGE_EXPORT_DIRECTORY ExportDirectory = NULL;
    PVOID DllBase = NULL;


    PCRACK_LDR_DATA_TABLE_ENTRY LdrEntry;
    for (LdrEntry = (PCRACK_LDR_DATA_TABLE_ENTRY)Ldr->Reserved2[1]; LdrEntry->DllBase != NULL; LdrEntry = (PCRACK_LDR_DATA_TABLE_ENTRY)LdrEntry->Reserved1[0])
    {
        DllBase = LdrEntry->DllBase;
        PIMAGE_DOS_HEADER DosHeader = (PIMAGE_DOS_HEADER)DllBase;
        PIMAGE_NT_HEADERS NtHeaders = CRACK_RVA2VA(PIMAGE_NT_HEADERS, DllBase, DosHeader->e_lfanew);
        PIMAGE_DATA_DIRECTORY DataDirectory = (PIMAGE_DATA_DIRECTORY)NtHeaders->OptionalHeader.DataDirectory;
        DWORD VirtualAddress = DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
        if (VirtualAddress == 0) continue;

        ExportDirectory = (PIMAGE_EXPORT_DIRECTORY)CRACK_RVA2VA(ULONG_PTR, DllBase, VirtualAddress);

        // If this is NTDLL.dll, exit loop.
        PCHAR DllName = CRACK_RVA2VA(PCHAR, DllBase, ExportDirectory->Name);

        if ((*(ULONG*)DllName | 0x20202020) != 'ldtn') continue;
        if ((*(ULONG*)(DllName + 4) | 0x20202020) == 'ld.l') break;
    }

    return (DWORD)DllBase;
}