#pragma once


#ifndef CRACK_HEADER_H_
#define CRACK_HEADER_H_

#include <windows.h>

#define CRACK_SEED 0xEA1D6D6B
#define CRACK_ROL8(v) (v << 8 | v >> 24)
#define CRACK_ROR8(v) (v >> 8 | v << 24)
#define CRACK_ROX8(v) ((CRACK_SEED % 2) ? CRACK_ROL8(v) : CRACK_ROR8(v))
#define CRACK_MAX_ENTRIES 500
#define CRACK_RVA2VA(Type, DllBase, Rva) (Type)((ULONG_PTR) DllBase + Rva)

// Typedefs are prefixed to avoid pollution.

typedef struct _CRACK_SYSCALL_ENTRY
{
    DWORD Hash;
    DWORD Address;
} CRACK_SYSCALL_ENTRY, *PCRACK_SYSCALL_ENTRY;

typedef struct _CRACK_SYSCALL_LIST
{
    DWORD Count;
    CRACK_SYSCALL_ENTRY Entries[CRACK_MAX_ENTRIES];
} CRACK_SYSCALL_LIST, *PCRACK_SYSCALL_LIST;

typedef struct _CRACK_PEB_LDR_DATA {
	BYTE Reserved1[8];
	PVOID Reserved2[3];
	LIST_ENTRY InMemoryOrderModuleList;
} CRACK_PEB_LDR_DATA, *PCRACK_PEB_LDR_DATA;

typedef struct _CRACK_LDR_DATA_TABLE_ENTRY {
	PVOID Reserved1[2];
	LIST_ENTRY InMemoryOrderLinks;
	PVOID Reserved2[2];
	PVOID DllBase;
} CRACK_LDR_DATA_TABLE_ENTRY, *PCRACK_LDR_DATA_TABLE_ENTRY;

typedef struct _CRACK_PEB {
	BYTE Reserved1[2];
	BYTE BeingDebugged;
	BYTE Reserved2[1];
	PVOID Reserved3[2];
	PCRACK_PEB_LDR_DATA Ldr;
} CRACK_PEB, *PCRACK_PEB;

DWORD CRACK_Hash_Sys_call(PCSTR FunctionName);
BOOL CRACK_Populate_Syscall_List(void);
EXTERN_C DWORD CRACK_SNumber(DWORD CRACK_H);
EXTERN_C DWORD CRACK_Get_Base_N(DWORD CRACK_H);

#ifndef InitializeObjectAttributes
#define InitializeObjectAttributes( k, l, m, n, o ) { \
	(k)->Length = sizeof( OBJECT_ATTRIBUTES );        \
	(k)->RootDirectory = n;                           \
	(k)->Attributes = m;                              \
	(k)->ObjectName = l;                              \
	(k)->SecurityDescriptor = o;                      \
	(k)->SecurityQualityOfService = NULL;             \
}
#endif

typedef struct _UNICODE_STRING
{
	USHORT Length;
	USHORT MaximumLength;
	PWSTR  Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

typedef struct _PS_ATTRIBUTE
{
	ULONG  Attribute;
	SIZE_T Size;
	union
	{
		ULONG Value;
		PVOID ValuePtr;
	} u1;
	PSIZE_T ReturnLength;
} PS_ATTRIBUTE, *PPS_ATTRIBUTE;

typedef struct _OBJECT_ATTRIBUTES
{
	ULONG           Length;
	HANDLE          RootDirectory;
	PUNICODE_STRING ObjectName;
	ULONG           Attributes;
	PVOID           SecurityDescriptor;
	PVOID           SecurityQualityOfService;
} OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;

typedef struct _CLIENT_ID
{
	HANDLE UniqueProcess;
	HANDLE UniqueThread;
} CLIENT_ID, *PCLIENT_ID;

typedef struct _PS_ATTRIBUTE_LIST
{
	SIZE_T       TotalLength;
	PS_ATTRIBUTE Attributes[1];
} PS_ATTRIBUTE_LIST, *PPS_ATTRIBUTE_LIST;

EXTERN_C NTSTATUS CRACK_NtOP(
	OUT PHANDLE ProcessHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes,
	IN PCLIENT_ID ClientId OPTIONAL);

EXTERN_C NTSTATUS CRACK_NtCTE(
	OUT PHANDLE ThreadHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
	IN HANDLE ProcessHandle,
	IN PVOID StartRoutine,
	IN PVOID Argument OPTIONAL,
	IN ULONG CreateFlags,
	IN SIZE_T ZeroBits,
	IN SIZE_T StackSize,
	IN SIZE_T MaximumStackSize,
	IN PPS_ATTRIBUTE_LIST AttributeList OPTIONAL);

EXTERN_C NTSTATUS CRACK_NtWVM(
	IN HANDLE ProcessHandle,
	IN PVOID BaseAddress,
	IN PVOID Buffer,
	IN SIZE_T NumberOfBytesToWrite,
	OUT PSIZE_T NumberOfBytesWritten OPTIONAL);

EXTERN_C NTSTATUS CRACK_NtAVM(
	IN HANDLE ProcessHandle,
	IN OUT PVOID * BaseAddress,
	IN ULONG ZeroBits,
	IN OUT PSIZE_T RegionSize,
	IN ULONG AllocationType,
	IN ULONG Protect);

EXTERN_C NTSTATUS CRACK_NtPVM(
	IN HANDLE ProcessHandle,
	IN OUT PVOID * BaseAddress,
	IN OUT PSIZE_T RegionSize,
	IN ULONG NewProtect,
	OUT PULONG OldProtect);

#endif
