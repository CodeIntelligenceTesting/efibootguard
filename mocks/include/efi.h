#ifndef EFI_H
#define EFI_H

#include "stdint.h"

#define ENV_MEM_USERVARS 1
typedef void*               EFI_HANDLE;
typedef void*               EFI_IMAGE_UNLOAD;
typedef void                VOID;
typedef uint8_t             UINT8;
typedef uint16_t            UINT16;
typedef uint32_t            UINT32;
typedef uint64_t            UINT64;
typedef uint64_t            UINTN;
typedef char                CHAR8;
typedef char                CHAR16;
//typedef efi_system_table_t  EFI_SYSTEM_TABLE;
//typedef efi_char16_t        CHAR16;
typedef UINT64              EFI_LBA;
typedef unsigned char       BOOLEAN;
typedef int32_t             INT32;

typedef int EFI_STATUS;

#endif