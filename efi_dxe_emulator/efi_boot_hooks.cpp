/*
 * ______________________.___
 * \_   _____/\_   _____/|   |
 *  |    __)_  |    __)  |   |
 *  |        \ |     \   |   |
 * /_______  / \___  /   |___|
 *         \/      \/
 * ________  ____  ______________
 * \______ \ \   \/  /\_   _____/
 *  |    |  \ \     /  |    __)_
 *  |    `   \/     \  |        \
 *  /_______  /___/\  \/_______  /
 *          \/      \_/        \/
 * ___________             .__          __
 * \_   _____/ _____  __ __|  | _____ _/  |_  ___________
 *  |    __)_ /     \|  |  \  | \__  \\   __\/  _ \_  __ \
 *  |        \  Y Y  \  |  /  |__/ __ \|  | (  <_> )  | \/
 * /_______  /__|_|  /____/|____(____  /__|  \____/|__|
 *         \/      \/                \/
 *
 * EFI DXE Emulator
 *
 * An EFI DXE binary emulator based on Unicorn Engine
 *
 * Created by fG! on 26/04/16.
 * Copyright © 2016-2019 Pedro Vilaca. All rights reserved.
 * reverser@put.as - https://reverse.put.as
 *
 * efi_boot_hooks.c
 *
 * Emulated EFI Boot Services
 *
 * All advertising materials mentioning features or use of this software must display
 * the following acknowledgement: This product includes software developed by
 * Pedro Vilaca.
 *
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted provided that the following conditions are met:
 
 * 1. Redistributions of source code must retain the above copyright notice, this list
 * of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice, this
 * list of conditions and the following disclaimer in the documentation and/or
 * other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software must
 * display the following acknowledgement: This product includes software developed
 * by Pedro Vilaca.
 * 4. Neither the name of the author nor the names of its contributors may be
 * used to endorse or promote products derived from this software without specific
 * prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#include "efi_boot_hooks.h"

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <vector>

#include "pe_definitions.h"
#include "efi_definitions.h"
#include "logging.h"
#include "config.h"
#include "debugger.h"
#include "unicorn_hooks.h"
#include "string_ops.h"
#include "protocols.h"
#include "unicorn_macros.h"
#include "unicorn_utils.h"
#include "mem_utils.h"
#include "guids.h"
#include "events.h"
#include "loader.h"

static void hook_RaiseTPL(uc_engine *uc, uint64_t address, uint32_t size, void *user_data);
static void hook_RestoreTPL(uc_engine *uc, uint64_t address, uint32_t size, void *user_data);
static void hook_AllocatePages(uc_engine *uc, uint64_t address, uint32_t size, void *user_data);
static void hook_FreePages(uc_engine *uc, uint64_t address, uint32_t size, void *user_data);
static void hook_GetMemoryMap(uc_engine *uc, uint64_t address, uint32_t size, void *user_data);
static void hook_AllocatePool(uc_engine *uc, uint64_t address, uint32_t size, void *user_data);
static void hook_FreePool(uc_engine *uc, uint64_t address, uint32_t size, void *user_data);
static void hook_CreateEvent(uc_engine *uc, uint64_t address, uint32_t size, void *user_data);
static void hook_SetTimer(uc_engine *uc, uint64_t address, uint32_t size, void *user_data);
static void hook_WaitForEvent(uc_engine *uc, uint64_t address, uint32_t size, void *user_data);
static void hook_SignalEvent(uc_engine *uc, uint64_t address, uint32_t size, void *user_data);
static void hook_CloseEvent(uc_engine *uc, uint64_t address, uint32_t size, void *user_data);
static void hook_CheckEvent(uc_engine *uc, uint64_t address, uint32_t size, void *user_data);
static void hook_InstallProtocolInterface(uc_engine *uc, uint64_t address, uint32_t size, void *user_data);
static void hook_ReinstallProtocolInterface(uc_engine *uc, uint64_t address, uint32_t size, void *user_data);
static void hook_UninstallProtocolInterface(uc_engine *uc, uint64_t address, uint32_t size, void *user_data);
static void hook_HandleProtocol(uc_engine *uc, uint64_t address, uint32_t size, void *user_data);
static void hook_Reserved(uc_engine *uc, uint64_t address, uint32_t size, void *user_data);
static void hook_RegisterProtocolNotify(uc_engine *uc, uint64_t address, uint32_t size, void *user_data);
static void hook_LocateHandle(uc_engine *uc, uint64_t address, uint32_t size, void *user_data);
static void hook_LocateDevicePath(uc_engine *uc, uint64_t address, uint32_t size, void *user_data);
static void hook_InstallConfigurationTable(uc_engine *uc, uint64_t address, uint32_t size, void *user_data);
static void hook_LoadImage(uc_engine *uc, uint64_t address, uint32_t size, void *user_data);
static void hook_StartImage(uc_engine *uc, uint64_t address, uint32_t size, void *user_data);
static void hook_Exit(uc_engine *uc, uint64_t address, uint32_t size, void *user_data);
static void hook_UnloadImage(uc_engine *uc, uint64_t address, uint32_t size, void *user_data);
static void hook_ExitBootServices(uc_engine *uc, uint64_t address, uint32_t size, void *user_data);
static void hook_GetNextMonotonicCount(uc_engine *uc, uint64_t address, uint32_t size, void *user_data);
static void hook_Stall(uc_engine *uc, uint64_t address, uint32_t size, void *user_data);
static void hook_SetWatchdogTimer(uc_engine *uc, uint64_t address, uint32_t size, void *user_data);
static void hook_ConnectController(uc_engine *uc, uint64_t address, uint32_t size, void *user_data);
static void hook_DisconnectController(uc_engine *uc, uint64_t address, uint32_t size, void *user_data);
static void hook_OpenProtocol(uc_engine *uc, uint64_t address, uint32_t size, void *user_data);
static void hook_CloseProtocol(uc_engine *uc, uint64_t address, uint32_t size, void *user_data);
static void hook_OpenProtocolInformation(uc_engine *uc, uint64_t address, uint32_t size, void *user_data);
static void hook_ProtocolsPerHandle(uc_engine *uc, uint64_t address, uint32_t size, void *user_data);
static void hook_LocateHandleBuffer(uc_engine *uc, uint64_t address, uint32_t size, void *user_data);
static void hook_LocateProtocol(uc_engine *uc, uint64_t address, uint32_t size, void *user_data);
static void hook_InstallMultipleProtocolInterfaces(uc_engine *uc, uint64_t address, uint32_t size, void *user_data);
static void hook_UninstallMultipleProtocolInterfaces(uc_engine *uc, uint64_t address, uint32_t size, void *user_data);
static void hook_CalculateCrc32(uc_engine *uc, uint64_t address, uint32_t size, void *user_data);
static void hook_CopyMem(uc_engine *uc, uint64_t address, uint32_t size, void *user_data);
static void hook_SetMem(uc_engine *uc, uint64_t address, uint32_t size, void *user_data);
static void hook_CreateEventEx(uc_engine *uc, uint64_t address, uint32_t size, void *user_data);

struct _boot_hooks
{
    char name[64];
    int offset;
    void *hook;
    uint64_t addr;
};

struct _boot_hooks boot_hooks[] = {
    {
        .name = "RaiseTPL",
        .offset = offsetof(EFI_BOOT_SERVICES, RaiseTPL),
        .hook = (void*)hook_RaiseTPL
    },
    {
        .name = "RestoreTPL",
        .offset = offsetof(EFI_BOOT_SERVICES, RestoreTPL),
        .hook = (void*)hook_RestoreTPL
    },
    {
        .name = "AllocatePages",
        .offset = offsetof(EFI_BOOT_SERVICES, AllocatePages),
        .hook = (void*)hook_AllocatePages
    },
    {
        .name = "FreePages",
        .offset = offsetof(EFI_BOOT_SERVICES, FreePages),
        .hook = (void*)hook_FreePages
    },
    {
        .name = "GetMemoryMap",
        .offset = offsetof(EFI_BOOT_SERVICES, GetMemoryMap),
        .hook = (void*)hook_GetMemoryMap
    },
    {
        .name = "AllocatePool",
        .offset = offsetof(EFI_BOOT_SERVICES, AllocatePool),
        .hook = (void*)hook_AllocatePool
    },
    {
        .name = "FreePool",
        .offset = offsetof(EFI_BOOT_SERVICES, FreePool),
        .hook = (void*)hook_FreePool
    },
    {
        .name = "CreateEvent",
        .offset = offsetof(EFI_BOOT_SERVICES, CreateEvent),
        .hook = (void*)hook_CreateEvent
    },
    {
        .name = "SetTimer",
        .offset = offsetof(EFI_BOOT_SERVICES, SetTimer),
        .hook = (void*)hook_SetTimer
    },
    {
        .name = "WaitForEvent",
        .offset = offsetof(EFI_BOOT_SERVICES, WaitForEvent),
        .hook = (void*)hook_WaitForEvent
    },
    {
        .name = "SignalEvent",
        .offset = offsetof(EFI_BOOT_SERVICES, SignalEvent),
        .hook = (void*)hook_SignalEvent
    },
    {
        .name = "CloseEvent",
        .offset = offsetof(EFI_BOOT_SERVICES, CloseEvent),
        .hook = (void*)hook_CloseEvent
    },
    {
        .name = "CheckEvent",
        .offset = offsetof(EFI_BOOT_SERVICES, CheckEvent),
        .hook = (void*)hook_CheckEvent
    },
    {
        .name = "InstallProtocolInterface",
        .offset = offsetof(EFI_BOOT_SERVICES, InstallProtocolInterface),
        .hook = (void*)hook_InstallProtocolInterface
    },
    {
        .name = "ReinstallProtocolInterface",
        .offset = offsetof(EFI_BOOT_SERVICES, ReinstallProtocolInterface),
        .hook = (void*)hook_ReinstallProtocolInterface
    },
    {
        .name = "UninstallProtocolInterface",
        .offset = offsetof(EFI_BOOT_SERVICES, UninstallProtocolInterface),
        .hook = (void*)hook_UninstallProtocolInterface
    },
    {
        .name = "HandleProtocol",
        .offset = offsetof(EFI_BOOT_SERVICES, HandleProtocol),
        .hook = (void*)hook_HandleProtocol
    },
    {
        .name = "Reserved",
        .offset = offsetof(EFI_BOOT_SERVICES, Reserved),
        .hook = (void*)hook_Reserved
    },
    {
        .name = "RegisterProtocolNotify",
        .offset = offsetof(EFI_BOOT_SERVICES, RegisterProtocolNotify),
        .hook = (void*)hook_RegisterProtocolNotify
    },
    {
        .name = "LocateHandle",
        .offset = offsetof(EFI_BOOT_SERVICES, LocateHandle),
        .hook = (void*)hook_LocateHandle
    },
    {
        .name = "LocateDevicePath",
        .offset = offsetof(EFI_BOOT_SERVICES, LocateDevicePath),
        .hook = (void*)hook_LocateDevicePath
    },
    {
        .name = "InstallConfigurationTable",
        .offset = offsetof(EFI_BOOT_SERVICES, InstallConfigurationTable),
        .hook = (void*)hook_InstallConfigurationTable
    },
    {
        .name = "LoadImage",
        .offset = offsetof(EFI_BOOT_SERVICES, LoadImage),
        .hook = (void*)hook_LoadImage
    },
    {
        .name = "StartImage",
        .offset = offsetof(EFI_BOOT_SERVICES, StartImage),
        .hook = (void*)hook_StartImage
    },
    {
        .name = "Exit",
        .offset = offsetof(EFI_BOOT_SERVICES, Exit),
        .hook = (void*)hook_Exit
    },
    {
        .name = "UnloadImage",
        .offset = offsetof(EFI_BOOT_SERVICES, UnloadImage),
        .hook = (void*)hook_UnloadImage
    },
    {
        .name = "ExitBootServices",
        .offset = offsetof(EFI_BOOT_SERVICES, ExitBootServices),
        .hook = (void*)hook_ExitBootServices
    },
    {
        .name = "GetNextMonotonicCount",
        .offset = offsetof(EFI_BOOT_SERVICES, GetNextMonotonicCount),
        .hook = (void*)hook_GetNextMonotonicCount
    },
    {
        .name = "Stall",
        .offset = offsetof(EFI_BOOT_SERVICES, Stall),
        .hook = (void*)hook_Stall
    },
    {
        .name = "SetWatchdogTimer",
        .offset = offsetof(EFI_BOOT_SERVICES, SetWatchdogTimer),
        .hook = (void*)hook_SetWatchdogTimer
    },
    {
        .name = "ConnectController",
        .offset = offsetof(EFI_BOOT_SERVICES, ConnectController),
        .hook = (void*)hook_ConnectController
    },
    {
        .name = "DisconnectController",
        .offset = offsetof(EFI_BOOT_SERVICES, DisconnectController),
        .hook = (void*)hook_DisconnectController
    },
    {
        .name = "OpenProtocol",
        .offset = offsetof(EFI_BOOT_SERVICES, OpenProtocol),
        .hook = (void*)hook_OpenProtocol
    },
    {
        .name = "CloseProtocol",
        .offset = offsetof(EFI_BOOT_SERVICES, CloseProtocol),
        .hook = (void*)hook_CloseProtocol
    },
    {
        .name = "OpenProtocolInformation",
        .offset = offsetof(EFI_BOOT_SERVICES, OpenProtocolInformation),
        .hook = (void*)hook_OpenProtocolInformation
    },
    {
        .name = "ProtocolsPerHandle",
        .offset = offsetof(EFI_BOOT_SERVICES, ProtocolsPerHandle),
        .hook = (void*)hook_ProtocolsPerHandle
    },
    {
        .name = "LocateHandleBuffer",
        .offset = offsetof(EFI_BOOT_SERVICES, LocateHandleBuffer),
        .hook = (void*)hook_LocateHandleBuffer
    },
    {
        .name = "LocateProtocol",
        .offset = offsetof(EFI_BOOT_SERVICES, LocateProtocol),
        .hook = (void*)hook_LocateProtocol
    },
    {
        .name = "InstallMultipleProtocolInterfaces",
        .offset = offsetof(EFI_BOOT_SERVICES, InstallMultipleProtocolInterfaces),
        .hook = (void*)hook_InstallMultipleProtocolInterfaces
    },
    {
        .name = "UninstallMultipleProtocolInterfaces",
        .offset = offsetof(EFI_BOOT_SERVICES, UninstallMultipleProtocolInterfaces),
        .hook = (void*)hook_UninstallMultipleProtocolInterfaces
    },
    {
        .name = "CalculateCrc32",
        .offset = offsetof(EFI_BOOT_SERVICES, CalculateCrc32),
        .hook = (void*)hook_CalculateCrc32
    },
    {
        .name = "CopyMem",
        .offset = offsetof(EFI_BOOT_SERVICES, CopyMem),
        .hook = (void*)hook_CopyMem
    },
    {
        .name = "SetMem",
        .offset = offsetof(EFI_BOOT_SERVICES, SetMem),
        .hook = (void*)hook_SetMem
    },
    {
        .name = "CreateEventEx",
        .offset = offsetof(EFI_BOOT_SERVICES, CreateEventEx),
        .hook = (void*)hook_CreateEventEx
    }
};

int
install_boot_services(uc_engine *uc, uint64_t base_addr, size_t *out_count)
{
    uc_err err = UC_ERR_OK;
    
    /* create the Boot services table */
    EFI_BOOT_SERVICES boot_table = {0};
    
    int hook_size = HOOK_SIZE;
    
    uint64_t hooks_addr = base_addr + sizeof(EFI_BOOT_SERVICES);
    
    size_t array_size = sizeof(boot_hooks) / sizeof(*boot_hooks);
    for (int i = 0; i < array_size; i++)
    {
        *(uint64_t*)((char*)&boot_table + boot_hooks[i].offset) = (uint64_t)(hooks_addr + hook_size * i);
    }

    auto ret_bytes = static_cast<unsigned char *>(my_malloc(hook_size * array_size));
    memset(ret_bytes, 0xC3, hook_size * array_size);
    err = uc_mem_write(uc, hooks_addr, ret_bytes, hook_size * array_size);
    /* XXX: mem leak on ret_bytes but we will exit app anyway after this */
    VERIFY_UC_OPERATION_RET(err, 1, "Failed to write Boot Services hooks");
    
    for (int i = 0; i < array_size; i++)
    {
        boot_hooks[i].addr = hooks_addr + hook_size * i;
        add_unicorn_hook(uc, UC_HOOK_CODE, boot_hooks[i].hook, boot_hooks[i].addr, boot_hooks[i].addr);
    }
    
    err = uc_mem_write(uc, base_addr, (void*)&boot_table, sizeof(EFI_BOOT_SERVICES));
    /* XXX: mem leak on ret_bytes but we will exit app anyway after this */
    VERIFY_UC_OPERATION_RET(err, 1, "Failed to write Boot Services table");
    
    *out_count = array_size;
    
    free(ret_bytes);
    
    return 0;
}

char *
lookup_boot_services_table(int offset)
{
    size_t array_size = sizeof(boot_hooks) / sizeof(*boot_hooks);
    for (int i = 0; i < array_size; i++)
    {
        if (boot_hooks[i].offset == offset)
        {
            return boot_hooks[i].name;
        }
    }
    return NULL;
}

uint64_t
lookup_boot_services_table(std::string_view name)
{
    size_t array_size = sizeof(boot_hooks) / sizeof(*boot_hooks);
    for (int i = 0; i < array_size; i++)
    {
        if (name == boot_hooks[i].name)
        {
            return boot_hooks[i].addr;
        }
    }
    return NULL;
}

/*
 * EFI_TPL(EFIAPI * EFI_RAISE_TPL) (IN EFI_TPL NewTpl)
 */
static void
hook_RaiseTPL(uc_engine *uc, uint64_t address, uint32_t size, void *user_data)
{
    uc_err err = UC_ERR_OK;
    
    LOG_UC_BACKTRACE(uc, "RaiseTPL()");
    
    /* return value */
    /* return always TPL_APPLICATION */
    uint64_t r_rax = 4;
    err = uc_reg_write(uc, UC_X86_REG_RAX, &r_rax);
    VERIFY_UC_OPERATION_VOID(err, "Failed to write RAX return value");
}

/*
 * VOID(EFIAPI * EFI_RESTORE_TPL) (IN EFI_TPL OldTpl)
 */
static void
hook_RestoreTPL(uc_engine *uc, uint64_t address, uint32_t size, void *user_data)
{
    LOG_UC_BACKTRACE(uc, "RestoreTPL()");
}

/*
 * EFI_STATUS(EFIAPI * EFI_ALLOCATE_PAGES) (IN EFI_ALLOCATE_TYPE Type, IN EFI_MEMORY_TYPE MemoryType, IN UINTN Pages, IN OUT EFI_PHYSICAL_ADDRESS *Memory)
 */
static void
hook_AllocatePages(uc_engine *uc, uint64_t address, uint32_t size, void *user_data)
{
    uc_err err = UC_ERR_OK;

    static uint64_t current_pool_addr = EFI_HEAP_ADDRESS;

    LOG_UC_BACKTRACE(uc, "AllocatePages()");

    uint64_t r_rcx = 0;     /* Type */
    uint64_t r_rdx = 0;     /* MemoryType */
    uint64_t r_r8 = 0;      /* Pages */
    uint64_t r_r9 = 0;      /* Memory */

    err = uc_reg_read(uc, UC_X86_REG_R8, &r_r8);
    VERIFY_UC_OPERATION_VOID(err, "Failed to read R8 register");
    uint32_t Size = (uint32_t)r_r8 * 0x1000;
    if (Size == 0)
    {
        ERROR_MSG("Request size to AllocatePages is zero bytes.");
        /* return value */
        uint64_t r_rax = EFI_INVALID_PARAMETER;
        err = uc_reg_write(uc, UC_X86_REG_RAX, &r_rax);
        VERIFY_UC_OPERATION_NORET(err, "Failed to read Unicorn register")
            return;
    }
    DEBUG_MSG("Requested size to AllocatePages() is 0x%x pages", (uint32_t)r_r8);

    /* Unicorn only accepts 4kb pages */
    uint32_t remainder = 0;
    /* we add the missing NULL byte */
    remainder = Size % 4096;

    if (remainder != 0)
    {
        /* add alignment */
        /* this will most probably always be required */
        Size += 4096 - remainder;
        DEBUG_MSG("Size is now %d", Size);
    }
    /* "allocate" Unicorn memory inside our already allocated "heap" area */
    uint64_t allocated_mem = current_pool_addr;
    current_pool_addr += Size;

    uint64_t Buffer = 0;
    err = uc_reg_read(uc, UC_X86_REG_R9, &r_r9);
    VERIFY_UC_OPERATION_VOID(err, "Failed to read R9 register");
    /*
     * we need to allocate memory inside the Unicorn machine
     * and set the pointer there
     */
    err = uc_mem_read(uc, r_r9, &Buffer, sizeof(Buffer));
    VERIFY_UC_OPERATION_NORET(err, "Failed to read from Unicorn memory")
        DEBUG_MSG("Buffer address 0x%llx 0x%llx", Buffer, r_r9);
    err = uc_mem_write(uc, r_r9, &allocated_mem, sizeof(allocated_mem));
    VERIFY_UC_OPERATION_NORET(err, "Failed to write to Unicorn memory")
        err = uc_mem_read(uc, r_r9, &Buffer, sizeof(Buffer));
    VERIFY_UC_OPERATION_NORET(err, "Failed to read from Unicorn memory")
        DEBUG_MSG("Buffer address 0x%llx 0x%llx", Buffer, r_r9);

    /* return value */
    uint64_t r_rax = EFI_SUCCESS;
    err = uc_reg_write(uc, UC_X86_REG_RAX, &r_rax);
    VERIFY_UC_OPERATION_VOID(err, "Failed to write RAX return value");
}

/*
 * EFI_STATUS(EFIAPI * EFI_FREE_PAGES) (IN EFI_PHYSICAL_ADDRESS Memory, IN UINTN Pages)
 */
static void
hook_FreePages(uc_engine *uc, uint64_t address, uint32_t size, void *user_data)
{
    uc_err err = UC_ERR_OK;
    
    LOG_UC_BACKTRACE(uc, "FreePages()");
    
    /* return value */
    uint64_t r_rax = EFI_SUCCESS;
    err = uc_reg_write(uc, UC_X86_REG_RAX, &r_rax);
    VERIFY_UC_OPERATION_VOID(err, "Failed to write RAX return value");
}

/*
 * EFI_STATUS(EFIAPI * EFI_GET_MEMORY_MAP) (IN OUT UINTN *MemoryMapSize, IN OUT EFI_MEMORY_DESCRIPTOR *MemoryMap, OUT UINTN *MapKey, OUT UINTN *DescriptorSize, OUT UINT32 *DescriptorVersion)
 */
static void
hook_GetMemoryMap(uc_engine *uc, uint64_t address, uint32_t size, void *user_data)
{
    uc_err err = UC_ERR_OK;
 
    LOG_UC_BACKTRACE(uc, "GetMemoryMap()");
    
    /* return value */
    uint64_t r_rax = EFI_SUCCESS;
    err = uc_reg_write(uc, UC_X86_REG_RAX, &r_rax);
    VERIFY_UC_OPERATION_VOID(err, "Failed to write RAX return value");
}

/*
 * EFI_STATUS(EFIAPI * EFI_ALLOCATE_POOL) (IN EFI_MEMORY_TYPE PoolType, IN UINTN Size, OUT VOID **Buffer)
 */
static void
hook_AllocatePool(uc_engine *uc, uint64_t address, uint32_t size, void *user_data)
{
    uc_err err = UC_ERR_OK;
    
    static uint64_t current_pool_addr = EFI_HEAP_ADDRESS;
    
    LOG_UC_BACKTRACE(uc, "AllocatePool()");

    uint64_t r_rcx = 0;     /* PoolType */
    uint64_t r_rdx = 0;     /* Size */
    uint64_t r_r8 = 0;      /* Buffer */
    
    err = uc_reg_read(uc, UC_X86_REG_RDX, &r_rdx);
    VERIFY_UC_OPERATION_VOID(err, "Failed to read RDX register");
    uint32_t Size = (uint32_t)r_rdx;
    if (Size == 0)
    {
        ERROR_MSG("Request size to AllocatePool is zero bytes.");
        /* return value */
        uint64_t r_rax = EFI_INVALID_PARAMETER;
        err = uc_reg_write(uc, UC_X86_REG_RAX, &r_rax);
        VERIFY_UC_OPERATION_NORET(err, "Failed to read Unicorn register")
        return;
    }
    DEBUG_MSG("Requested size to AllocatePool() is 0x%x", (uint32_t)r_rdx);
    
    /* Unicorn only accepts 4kb pages */
    uint32_t remainder = 0;
    /* we add the missing NULL byte */
    remainder = Size % 4096;

    if (remainder != 0)
    {
        /* add alignment */
        /* this will most probably always be required */
        Size += 4096 - remainder;
        DEBUG_MSG("Size is now %d", Size);
    }
    /* "allocate" Unicorn memory inside our already allocated "heap" area */
    uint64_t allocated_mem = current_pool_addr;
    current_pool_addr += Size;
    
    uint64_t Buffer = 0;
    err = uc_reg_read(uc, UC_X86_REG_R8, &r_r8);
    VERIFY_UC_OPERATION_VOID(err, "Failed to read R8 register");
    /*
     * we need to allocate memory inside the Unicorn machine
     * and set the pointer there
     */
    err = uc_mem_read(uc, r_r8, &Buffer, sizeof(Buffer));
    VERIFY_UC_OPERATION_NORET(err, "Failed to read from Unicorn memory")
    DEBUG_MSG("Buffer address 0x%llx 0x%llx", Buffer, r_r8);
    err = uc_mem_write(uc, r_r8, &allocated_mem, sizeof(allocated_mem));
    VERIFY_UC_OPERATION_NORET(err, "Failed to write to Unicorn memory")
    err = uc_mem_read(uc, r_r8, &Buffer, sizeof(Buffer));
    VERIFY_UC_OPERATION_NORET(err, "Failed to read from Unicorn memory")
    DEBUG_MSG("Buffer address 0x%llx 0x%llx", Buffer, r_r8);

    /* return value */
    uint64_t r_rax = EFI_SUCCESS;
    err = uc_reg_write(uc, UC_X86_REG_RAX, &r_rax);
    VERIFY_UC_OPERATION_VOID(err, "Failed to write RAX return value");
}

/*
 * EFI_STATUS(EFIAPI * EFI_FREE_POOL) (IN VOID *Buffer)
 */
static void
hook_FreePool(uc_engine *uc, uint64_t address, uint32_t size, void *user_data)
{
    uc_err err = UC_ERR_OK;
    
    LOG_UC_BACKTRACE(uc, "FreePool()");
    
    /* return value */
    uint64_t r_rax = EFI_SUCCESS;
    err = uc_reg_write(uc, UC_X86_REG_RAX, &r_rax);
    VERIFY_UC_OPERATION_VOID(err, "Failed to write RAX return value");
}

/*
 * EFI_STATUS(EFIAPI * EFI_CREATE_EVENT) (IN UINT32 Type, IN EFI_TPL NotifyTpl, IN EFI_EVENT_NOTIFY NotifyFunction, IN VOID *NotifyContext, OUT EFI_EVENT *Event)
 */
static void
hook_CreateEvent(uc_engine *uc, uint64_t address, uint32_t size, void *user_data)
{
    uc_err err = UC_ERR_OK;
    
    LOG_UC_BACKTRACE(uc, "CreateEvent()");
    
    /* Type */
    uint32_t r_ecx = 0;
    err = uc_reg_read(uc, UC_X86_REG_ECX, &r_ecx);
    VERIFY_UC_OPERATION_VOID(err, "Failed to read ECX register");

    /* NotifyTpl */
    uint64_t r_rdx = 0;
    err = uc_reg_read(uc, UC_X86_REG_RDX, &r_rdx);
    VERIFY_UC_OPERATION_VOID(err, "Failed to read RDX register");

    /* NotifyFunction */
    uint64_t r_r8 = 0;
    err = uc_reg_read(uc, UC_X86_REG_R8, &r_r8);
    VERIFY_UC_OPERATION_VOID(err, "Failed to read R8 register");

    /* NotifyContext */
    uint64_t r_r9 = 0;
    err = uc_reg_read(uc, UC_X86_REG_R9, &r_r9);
    VERIFY_UC_OPERATION_VOID(err, "Failed to read R9 register");

    /* Event */
    uint64_t r_rsp = 0;
    err = uc_reg_read(uc, UC_X86_REG_RSP, &r_rsp);
    VERIFY_UC_OPERATION_VOID(err, "Failed to read RSP register");

    uint64_t event_ptr = 0;
    err = uc_mem_read(uc, r_rsp + 5 * sizeof(uint64_t), &event_ptr, sizeof(event_ptr));
    VERIFY_UC_OPERATION_VOID(err, "Failed to read memory");

    DEBUG_MSG("\tType: 0x%x", r_ecx);
    DEBUG_MSG("\tNotifyTpl: %d", r_rdx);
    DEBUG_MSG("\tNotifyFunction: 0x%p", r_r8);
    DEBUG_MSG("\tNotifyContext: 0x%p", r_r9);
    DEBUG_MSG("\tEventPointer: 0x%p", event_ptr);

    /* Write event handle */
    EFI_EVENT Event = create_efi_event(uc, r_ecx, r_rdx, (EFI_EVENT_NOTIFY)r_r8, (void*)r_r9);
    uc_mem_write(uc, event_ptr, &Event, sizeof(EFI_EVENT));

    /* return value */
    uint64_t r_rax = EFI_SUCCESS;
    err = uc_reg_write(uc, UC_X86_REG_RAX, &r_rax);
    VERIFY_UC_OPERATION_VOID(err, "Failed to write RAX return value");
}

/*
 * EFI_STATUS(EFIAPI * EFI_SET_TIMER) (IN EFI_EVENT Event, IN EFI_TIMER_DELAY Type, IN UINT64 TriggerTime)
 */
static void
hook_SetTimer(uc_engine *uc, uint64_t address, uint32_t size, void *user_data)
{
    uc_err err = UC_ERR_OK;
    
    LOG_UC_BACKTRACE(uc, "SetTimer()");
    
    /* return value */
    uint64_t r_rax = EFI_SUCCESS;
    err = uc_reg_write(uc, UC_X86_REG_RAX, &r_rax);
    VERIFY_UC_OPERATION_VOID(err, "Failed to write RAX return value");
}

/*
 * EFI_STATUS(EFIAPI * EFI_WAIT_FOR_EVENT) (IN UINTN NumberOfEvents, IN EFI_EVENT *Event, OUT UINTN *Index)
 */
static void
hook_WaitForEvent(uc_engine *uc, uint64_t address, uint32_t size, void *user_data)
{
    uc_err err = UC_ERR_OK;
    
    LOG_UC_BACKTRACE(uc, "WaitForEvent()");
    
    /* return value */
    uint64_t r_rax = EFI_SUCCESS;
    err = uc_reg_write(uc, UC_X86_REG_RAX, &r_rax);
    VERIFY_UC_OPERATION_VOID(err, "Failed to write RAX return value");
}

/*
 * EFI_STATUS(EFIAPI * EFI_SIGNAL_EVENT) (IN EFI_EVENT Event)
 */
static void
hook_SignalEvent(uc_engine *uc, uint64_t address, uint32_t size, void *user_data)
{
    uc_err err = UC_ERR_OK;
    
    LOG_UC_BACKTRACE(uc, "SignalEvent()");
    
    /* Event */
    uint64_t r_rcx = 0;
    err = uc_reg_read(uc, UC_X86_REG_RCX, &r_rcx);
    VERIFY_UC_OPERATION_VOID(err, "Failed to read RCX register");

    DEBUG_MSG("\tEvent: 0x%p", r_rcx);
    signal_efi_event(uc, (EFI_EVENT)r_rcx);

    /* return value */
    uint64_t r_rax = EFI_SUCCESS;
    err = uc_reg_write(uc, UC_X86_REG_RAX, &r_rax);
    VERIFY_UC_OPERATION_VOID(err, "Failed to write RAX return value");
}

/*
 * EFI_STATUS(EFIAPI * EFI_CLOSE_EVENT) (IN EFI_EVENT Event)
 */
static void
hook_CloseEvent(uc_engine *uc, uint64_t address, uint32_t size, void *user_data)
{
    uc_err err = UC_ERR_OK;
    
    LOG_UC_BACKTRACE(uc, "CloseEvent()");

    /* return value */
    uint64_t r_rax = EFI_SUCCESS;
    err = uc_reg_write(uc, UC_X86_REG_RAX, &r_rax);
    VERIFY_UC_OPERATION_VOID(err, "Failed to write RAX return value");
}

/*
 * EFI_STATUS(EFIAPI * EFI_CHECK_EVENT) (IN EFI_EVENT Event)
 */
static void
hook_CheckEvent(uc_engine *uc, uint64_t address, uint32_t size, void *user_data)
{
    uc_err err = UC_ERR_OK;
    
    LOG_UC_BACKTRACE(uc, "CheckEvent()");
    
    /* return value */
    uint64_t r_rax = EFI_SUCCESS;
    err = uc_reg_write(uc, UC_X86_REG_RAX, &r_rax);
    VERIFY_UC_OPERATION_VOID(err, "Failed to write RAX return value");
}

/*
 * EFI_STATUS(EFIAPI * EFI_INSTALL_PROTOCOL_INTERFACE) (IN OUT EFI_HANDLE *Handle, IN EFI_GUID *Protocol, IN EFI_INTERFACE_TYPE InterfaceType, IN VOID *Interface)
 */
static void
hook_InstallProtocolInterface(uc_engine *uc, uint64_t address, uint32_t size, void *user_data)
{
    uc_err err = UC_ERR_OK;
    uint64_t ret = EFI_SUCCESS;

    LOG_UC_BACKTRACE(uc, "InstallProtocolInterface()");
    
    uint64_t r_rcx = 0;     /* Handle */
    uint64_t r_rdx = 0;     /* Protocol */
    uint64_t r_r8 = 0;      /* InterfaceType */
    uint64_t r_r9 = 0;      /* Interface */

    /* read Handle */
    err = uc_reg_read(uc, UC_X86_REG_RCX, &r_rcx);
    if (err != UC_ERR_OK)
    {
        ERROR_MSG("Failed to read Handle from RCX.");
        return;
    }

    EFI_GUID Protocol = {0};
    /* read Protocol location */
    err = uc_reg_read(uc, UC_X86_REG_RDX, &r_rdx);
    if (err != UC_ERR_OK)
    {
        ERROR_MSG("Failed to read Protocol location from RDX.");
        return;
    }

    err = uc_mem_read(uc, r_rdx, &Protocol, sizeof(EFI_GUID));
    if (err != UC_ERR_OK)
    {
        ERROR_MSG("Failed to read Protocol.");
        return;
    }

    /* read InterfaceType */
    err = uc_reg_read(uc, UC_X86_REG_R8, &r_r8);
    if (err != UC_ERR_OK)
    {
        ERROR_MSG("Failed to read InterfaceType from R8.");
        return;
    }

    /* read Interface */
    err = uc_reg_read(uc, UC_X86_REG_R9, &r_r9);
    if (err != UC_ERR_OK)
    {
        ERROR_MSG("Failed to read Interface from R9.");
        return;
    }
    
    if (r_rcx == 0 || r_rdx == 0)
    {
        ERROR_MSG("Handle or Protocol are NULL.");
        ret = EFI_INVALID_PARAMETER;
        goto out;
    }
    
    EFI_GUID *guid = &Protocol;
    OUTPUT_MSG("Requested Protocol: %s (%s)", guid_to_string(guid), get_guid_friendly_name(*guid));
    
    if (r_r8 != EFI_NATIVE_INTERFACE)
    {
        ERROR_MSG("Invalid InterfaceType.");
        ret = EFI_INVALID_PARAMETER;
        goto out;
    }
    
    DEBUG_MSG("Interface address 0x%llx", r_r9);
    
    if (add_protocol(guid, r_r9) != 0)
    {
        ret = EFI_OUT_OF_RESOURCES;
        goto out;
    }
    
    ret = EFI_SUCCESS;
    OUTPUT_MSG("Installed Protocol: %08X-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X",
               guid->Data1, guid->Data2, guid->Data3,
               guid->Data4[0], guid->Data4[1], guid->Data4[2], guid->Data4[3],
               guid->Data4[4], guid->Data4[5], guid->Data4[6], guid->Data4[7]);

out:
    /* return value */
    err = uc_reg_write(uc, UC_X86_REG_RAX, &ret);
    VERIFY_UC_OPERATION_VOID(err, "Failed to write RAX return value");
}

/*
 * EFI_STATUS(EFIAPI * EFI_REINSTALL_PROTOCOL_INTERFACE) (IN EFI_HANDLE Handle, IN EFI_GUID *Protocol, IN VOID *OldInterface, IN VOID *NewInterface)
 */
static void
hook_ReinstallProtocolInterface(uc_engine *uc, uint64_t address, uint32_t size, void *user_data)
{
    uc_err err = UC_ERR_OK;
    
    LOG_UC_BACKTRACE(uc, "ReinstallProtocolInterface()");
    
    /* return value */
    uint64_t r_rax = EFI_SUCCESS;
    err = uc_reg_write(uc, UC_X86_REG_RAX, &r_rax);
    VERIFY_UC_OPERATION_VOID(err, "Failed to write RAX return value");
}

/*
 * EFI_STATUS(EFIAPI * EFI_UNINSTALL_PROTOCOL_INTERFACE) (IN EFI_HANDLE Handle, IN EFI_GUID *Protocol, IN VOID *Interface)
 */
static void
hook_UninstallProtocolInterface(uc_engine *uc, uint64_t address, uint32_t size, void *user_data)
{
    uc_err err = UC_ERR_OK;
    
    LOG_UC_BACKTRACE(uc, "UninstallProtocolInterface()");
    
    /* return value */
    uint64_t r_rax = EFI_SUCCESS;
    err = uc_reg_write(uc, UC_X86_REG_RAX, &r_rax);
    VERIFY_UC_OPERATION_VOID(err, "Failed to write RAX return value");
}

/*
 * EFI_STATUS(EFIAPI * EFI_HANDLE_PROTOCOL) (IN EFI_HANDLE Handle, IN EFI_GUID *Protocol, OUT VOID **Interface)
 */
static void
hook_HandleProtocol(uc_engine *uc, uint64_t address, uint32_t size, void *user_data)
{
    uc_err err = UC_ERR_OK;
    uint64_t ret = EFI_SUCCESS;
    
    LOG_UC_BACKTRACE(uc, "HandleProtocol()");
    
    uint64_t r_rdx = 0;
    err = uc_reg_read(uc, UC_X86_REG_RDX, &r_rdx);
    VERIFY_UC_OPERATION_VOID(err, "Failed to read RDX value");

    EFI_GUID Protocol = { 0 };
    err = uc_mem_read(uc, r_rdx, &Protocol, sizeof(Protocol));
    VERIFY_UC_OPERATION_VOID(err, "Failed to read memory at RDX");

    OUTPUT_MSG("Requested Protocol: %s (%s)",
        guid_to_string(&Protocol), get_guid_friendly_name(Protocol));

    uint64_t t_interface = 0;
    if (locate_protocol(&Protocol, &t_interface) != 0)
    {
        ret = EFI_NOT_FOUND;
        goto out;
    }

    ret = EFI_SUCCESS;

out:
    /* interface pointer */
    uint64_t r_r8 = 0;
    err = uc_reg_read(uc, UC_X86_REG_R8, &r_r8);
    VERIFY_UC_OPERATION_VOID(err, "Failed to read R8 value");

    err = uc_mem_write(uc, r_r8, &t_interface, sizeof(t_interface));
    VERIFY_UC_OPERATION_VOID(err, "Failed to write interface pointer");

    /* return value */
    err = uc_reg_write(uc, UC_X86_REG_RAX, &ret);
    VERIFY_UC_OPERATION_VOID(err, "Failed to write RAX return value");
}

static void
hook_Reserved(uc_engine *uc, uint64_t address, uint32_t size, void *user_data)
{
    LOG_UC_BACKTRACE(uc, "Reserved()");
}

/*
 * EFI_STATUS(EFIAPI * EFI_REGISTER_PROTOCOL_NOTIFY) (IN EFI_GUID *Protocol, IN EFI_EVENT Event, OUT VOID **Registration)
 */
static void
hook_RegisterProtocolNotify(uc_engine *uc, uint64_t address, uint32_t size, void *user_data)
{
    uc_err err = UC_ERR_OK;
    
    LOG_UC_BACKTRACE(uc, "RegisterProtocolNotify()");
    
    /* read Protocol */
    uint64_t r_rcx = 0;
    err = uc_reg_read(uc, UC_X86_REG_RCX, &r_rcx);
    VERIFY_UC_OPERATION_VOID(err, "Failed to read RCX register");

    EFI_GUID Protocol = { 0 };
    err = uc_mem_read(uc, r_rcx, &Protocol, sizeof(Protocol));
    VERIFY_UC_OPERATION_VOID(err, "Failed to read Protocol");

    DEBUG_MSG("\tProtocol: %s (%s)", guid_to_string(&Protocol), get_guid_friendly_name(Protocol));

    /* return value */
    uint64_t r_rax = EFI_SUCCESS;
    err = uc_reg_write(uc, UC_X86_REG_RAX, &r_rax);
    VERIFY_UC_OPERATION_VOID(err, "Failed to write RAX return value");
}

/*
 * EFI_STATUS(EFIAPI * EFI_LOCATE_HANDLE) (IN EFI_LOCATE_SEARCH_TYPE SearchType, IN EFI_GUID *Protocol, OPTIONAL IN VOID *SearchKey, OPTIONAL IN OUT UINTN *BufferSize, OUT EFI_HANDLE *Buffer)
 */
static void
hook_LocateHandle(uc_engine *uc, uint64_t address, uint32_t size, void *user_data)
{
    uc_err err = UC_ERR_OK;
    
    LOG_UC_BACKTRACE(uc, "LocateHandle()");
    
    /* return value */
    uint64_t r_rax = EFI_SUCCESS;
    err = uc_reg_write(uc, UC_X86_REG_RAX, &r_rax);
    VERIFY_UC_OPERATION_VOID(err, "Failed to write RAX return value");
}

/*
 * EFI_STATUS(EFIAPI * EFI_LOCATE_DEVICE_PATH) (IN EFI_GUID *Protocol, IN OUT EFI_DEVICE_PATH_PROTOCOL **DevicePath, OUT EFI_HANDLE *Device)
 */
static void
hook_LocateDevicePath(uc_engine *uc, uint64_t address, uint32_t size, void *user_data)
{
    uc_err err = UC_ERR_OK;
    
    LOG_UC_BACKTRACE(uc, "LocateDevicePath()");
    
    /* return value */
    uint64_t r_rax = EFI_SUCCESS;
    err = uc_reg_write(uc, UC_X86_REG_RAX, &r_rax);
    VERIFY_UC_OPERATION_VOID(err, "Failed to write RAX return value");
}

/*
 * EFI_STATUS(EFIAPI * EFI_INSTALL_CONFIGURATION_TABLE) (IN EFI_GUID *Guid, IN VOID *Table)
 */
static void
hook_InstallConfigurationTable(uc_engine *uc, uint64_t address, uint32_t size, void *user_data)
{
    uc_err err = UC_ERR_OK;
    
    LOG_UC_BACKTRACE(uc, "InstallConfigurationTable()");
    
    /* return value */
    uint64_t r_rax = EFI_SUCCESS;
    err = uc_reg_write(uc, UC_X86_REG_RAX, &r_rax);
    VERIFY_UC_OPERATION_VOID(err, "Failed to write RAX return value");
}

/*
 * EFI_STATUS(EFIAPI * EFI_IMAGE_LOAD) (IN BOOLEAN BootPolicy, IN EFI_HANDLE ParentImageHandle, IN EFI_DEVICE_PATH_PROTOCOL *DevicePath, IN VOID *SourceBuffer OPTIONAL, IN UINTN SourceSize, OUT EFI_HANDLE *ImageHandle)
 */
static void
hook_LoadImage(uc_engine *uc, uint64_t address, uint32_t size, void *user_data)
{
    uc_err err = UC_ERR_OK;
    
    LOG_UC_BACKTRACE(uc, "LoadImage()");
    
    /* return value */
    uint64_t r_rax = EFI_SUCCESS;
    err = uc_reg_write(uc, UC_X86_REG_RAX, &r_rax);
    VERIFY_UC_OPERATION_VOID(err, "Failed to write RAX return value");
}

/*
 * EFI_STATUS(EFIAPI * EFI_IMAGE_START) (IN EFI_HANDLE ImageHandle, OUT UINTN *ExitDataSize, OUT CHAR16 **ExitData OPTIONAL)
 */
static void
hook_StartImage(uc_engine *uc, uint64_t address, uint32_t size, void *user_data)
{
    uc_err err = UC_ERR_OK;
    
    LOG_UC_BACKTRACE(uc, "StartImage()");
    
    /* return value */
    uint64_t r_rax = EFI_SUCCESS;
    err = uc_reg_write(uc, UC_X86_REG_RAX, &r_rax);
    VERIFY_UC_OPERATION_VOID(err, "Failed to write RAX return value");
}

/*
 * EFI_STATUS(EFIAPI * EFI_EXIT) (IN EFI_HANDLE ImageHandle, IN EFI_STATUS ExitStatus, IN UINTN ExitDataSize, IN CHAR16 *ExitData OPTIONAL)
 */
static void
hook_Exit(uc_engine *uc, uint64_t address, uint32_t size, void *user_data)
{
    uc_err err = UC_ERR_OK;
    
    LOG_UC_BACKTRACE(uc, "Exit()");
    
    /* return value */
    uint64_t r_rax = EFI_SUCCESS;
    err = uc_reg_write(uc, UC_X86_REG_RAX, &r_rax);
    VERIFY_UC_OPERATION_VOID(err, "Failed to write RAX return value");
}

/*
 * EFI_STATUS(EFIAPI * EFI_IMAGE_UNLOAD) (IN EFI_HANDLE ImageHandle)
 */
static void
hook_UnloadImage(uc_engine *uc, uint64_t address, uint32_t size, void *user_data)
{
    uc_err err = UC_ERR_OK;
    
    LOG_UC_BACKTRACE(uc, "UnloadImage()");
    
    /* return value */
    uint64_t r_rax = EFI_SUCCESS;
    err = uc_reg_write(uc, UC_X86_REG_RAX, &r_rax);
    VERIFY_UC_OPERATION_VOID(err, "Failed to write RAX return value");
}

/*
 * EFI_STATUS(EFIAPI * EFI_EXIT_BOOT_SERVICES) (IN EFI_HANDLE ImageHandle, IN UINTN MapKey)
 */
static void
hook_ExitBootServices(uc_engine *uc, uint64_t address, uint32_t size, void *user_data)
{
    uc_err err = UC_ERR_OK;
    
    LOG_UC_BACKTRACE(uc, "ExitBootServices()");
    
    /* return value */
    uint64_t r_rax = EFI_SUCCESS;
    err = uc_reg_write(uc, UC_X86_REG_RAX, &r_rax);
    VERIFY_UC_OPERATION_VOID(err, "Failed to write RAX return value");
}

uint64_t gCurrentMonotonicCount = 0;

/*
 * EFI_STATUS(EFIAPI * EFI_GET_NEXT_MONOTONIC_COUNT) (OUT UINT64 *Count)
 */
static void
hook_GetNextMonotonicCount(uc_engine *uc, uint64_t address, uint32_t size, void *user_data)
{
    uint64_t ret = EFI_SUCCESS;
    uc_err err = UC_ERR_OK;

    LOG_UC_BACKTRACE(uc, "GetNextMonotonicCount()");
    
    uint64_t r_rcx = 0;     /* Count */
    err = uc_reg_read(uc, UC_X86_REG_RCX, &r_rcx);
    if (err != UC_ERR_OK)
    {
        DEBUG_MSG("Failed to read RCX register: %s", uc_strerror(err));
        ret = EFI_INVALID_PARAMETER;
        goto out;
    }
    /* test if Count is NULL */
    if (r_rcx == 0)
    {
        ret = EFI_INVALID_PARAMETER;
        goto out;
    }
    
    err = uc_mem_write(uc, r_rcx, &gCurrentMonotonicCount, sizeof(gCurrentMonotonicCount));
    if (err != UC_ERR_OK)
    {
        ERROR_MSG("Failed to write RCX register: %s", uc_strerror(err));
        ret = EFI_INVALID_PARAMETER;
        goto out;
    }
    
    gCurrentMonotonicCount++;

out:
    /* return value */
    err = uc_reg_write(uc, UC_X86_REG_RAX, &ret);
    VERIFY_UC_OPERATION_VOID(err, "Failed to write RAX return value");
}

/*
 * EFI_STATUS(EFIAPI * EFI_STALL) (IN UINTN Microseconds)
 */
static void
hook_Stall(uc_engine *uc, uint64_t address, uint32_t size, void *user_data)
{
    uc_err err = UC_ERR_OK;
    
    LOG_UC_BACKTRACE(uc, "Stall()");

    uint64_t r_rcx = 0;     /* Microseconds */
    err = uc_reg_read(uc, UC_X86_REG_RCX, &r_rcx);
    VERIFY_UC_OPERATION_VOID(err, "Failed to read RCX register");
    uint32_t Microseconds = (uint32_t) r_rcx;
    
    usleep(Microseconds);
    
    /* return value */
    uint64_t r_rax = EFI_SUCCESS;
    err = uc_reg_write(uc, UC_X86_REG_RAX, &r_rax);
    VERIFY_UC_OPERATION_VOID(err, "Failed to write RAX return value");
}

/*
 * EFI_STATUS(EFIAPI * EFI_SET_WATCHDOG_TIMER) (IN UINTN Timeout, IN UINT64 WatchdogCode, IN UINTN DataSize, IN CHAR16 *WatchdogData OPTIONAL)
 */
static void
hook_SetWatchdogTimer(uc_engine *uc, uint64_t address, uint32_t size, void *user_data)
{
    uc_err err = UC_ERR_OK;
    
    LOG_UC_BACKTRACE(uc, "SetWatchdogTimer()");
    
    /* return value */
    uint64_t r_rax = EFI_SUCCESS;
    err = uc_reg_write(uc, UC_X86_REG_RAX, &r_rax);
    VERIFY_UC_OPERATION_VOID(err, "Failed to write RAX return value");
}

/*
 * EFI_STATUS(EFIAPI * EFI_CONNECT_CONTROLLER) (IN EFI_HANDLE ControllerHandle, IN EFI_HANDLE *DriverImageHandle, OPTIONAL IN EFI_DEVICE_PATH_PROTOCOL *RemainingDevicePath, OPTIONAL IN BOOLEAN Recursive)
 */
static void
hook_ConnectController(uc_engine *uc, uint64_t address, uint32_t size, void *user_data)
{
    uc_err err = UC_ERR_OK;
    
    LOG_UC_BACKTRACE(uc, "ConnectController()");
    
    /* return value */
    uint64_t r_rax = EFI_SUCCESS;
    err = uc_reg_write(uc, UC_X86_REG_RAX, &r_rax);
    VERIFY_UC_OPERATION_VOID(err, "Failed to write RAX return value");
}

/*
 * EFI_STATUS(EFIAPI * EFI_DISCONNECT_CONTROLLER) (IN EFI_HANDLE ControllerHandle, IN EFI_HANDLE DriverImageHandle, OPTIONAL IN EFI_HANDLE ChildHandle OPTIONAL)
 */
static void
hook_DisconnectController(uc_engine *uc, uint64_t address, uint32_t size, void *user_data)
{
    uc_err err = UC_ERR_OK;
    
    LOG_UC_BACKTRACE(uc, "DisconnectController()");
    
    /* return value */
    uint64_t r_rax = EFI_SUCCESS;
    err = uc_reg_write(uc, UC_X86_REG_RAX, &r_rax);
    VERIFY_UC_OPERATION_VOID(err, "Failed to write RAX return value");
}

/*
 * EFI_STATUS(EFIAPI * EFI_OPEN_PROTOCOL) (IN EFI_HANDLE Handle, IN EFI_GUID *Protocol, OUT VOID **Interface, OPTIONAL IN EFI_HANDLE AgentHandle, IN EFI_HANDLE ControllerHandle, IN UINT32 Attributes)
 */
static void
hook_OpenProtocol(uc_engine *uc, uint64_t address, uint32_t size, void *user_data)
{
    uc_err err = UC_ERR_OK;
    
    LOG_UC_BACKTRACE(uc, "OpenProtocol()");
    
    /* return value */
    uint64_t r_rax = EFI_SUCCESS;
    err = uc_reg_write(uc, UC_X86_REG_RAX, &r_rax);
    VERIFY_UC_OPERATION_VOID(err, "Failed to write RAX return value");
}

/*
 * EFI_STATUS(EFIAPI * EFI_CLOSE_PROTOCOL) (IN EFI_HANDLE Handle, IN EFI_GUID *Protocol, IN EFI_HANDLE AgentHandle, IN EFI_HANDLE ControllerHandle)
 */
static void
hook_CloseProtocol(uc_engine *uc, uint64_t address, uint32_t size, void *user_data)
{
    uc_err err = UC_ERR_OK;
    
    LOG_UC_BACKTRACE(uc, "CloseProtocol()");
    
    /* return value */
    uint64_t r_rax = EFI_SUCCESS;
    err = uc_reg_write(uc, UC_X86_REG_RAX, &r_rax);
    VERIFY_UC_OPERATION_VOID(err, "Failed to write RAX return value");
}

/*
 * EFI_STATUS(EFIAPI * EFI_OPEN_PROTOCOL_INFORMATION) (IN EFI_HANDLE Handle, IN EFI_GUID *Protocol, OUT EFI_OPEN_PROTOCOL_INFORMATION_ENTRY **EntryBuffer, OUT UINTN *EntryCount)
 */
static void
hook_OpenProtocolInformation(uc_engine *uc, uint64_t address, uint32_t size, void *user_data)
{
    uc_err err = UC_ERR_OK;
    
    LOG_UC_BACKTRACE(uc, "OpenProtocolInformation()");
    
    /* return value */
    uint64_t r_rax = EFI_SUCCESS;
    err = uc_reg_write(uc, UC_X86_REG_RAX, &r_rax);
    VERIFY_UC_OPERATION_VOID(err, "Failed to write RAX return value");
}

/*
 * EFI_STATUS(EFIAPI * EFI_PROTOCOLS_PER_HANDLE) (IN EFI_HANDLE Handle, OUT EFI_GUID ***ProtocolBuffer, OUT UINTN *ProtocolBufferCount)
 */
static void
hook_ProtocolsPerHandle(uc_engine *uc, uint64_t address, uint32_t size, void *user_data)
{
    uc_err err = UC_ERR_OK;
    
    LOG_UC_BACKTRACE(uc, "ProtocolsPerHandle()");
    
    /* return value */
    uint64_t r_rax = EFI_SUCCESS;
    err = uc_reg_write(uc, UC_X86_REG_RAX, &r_rax);
    VERIFY_UC_OPERATION_VOID(err, "Failed to write RAX return value");
}

/*
 * EFI_STATUS(EFIAPI * EFI_LOCATE_HANDLE_BUFFER) (IN EFI_LOCATE_SEARCH_TYPE SearchType, IN EFI_GUID *Protocol, OPTIONAL IN VOID *SearchKey, OPTIONAL IN OUT UINTN *NoHandles, OUT EFI_HANDLE **Buffer)
 */
static void
hook_LocateHandleBuffer(uc_engine *uc, uint64_t address, uint32_t size, void *user_data)
{
    uc_err err = UC_ERR_OK;
    
    LOG_UC_BACKTRACE(uc, "LocateHandleBuffer()");

    /* read Protocol location */
    uint64_t r_rdx = 0;
    err = uc_reg_read(uc, UC_X86_REG_RDX, &r_rdx);
    VERIFY_UC_OPERATION_VOID(err, "Failed to read RCX register");
    
    EFI_GUID Protocol = { 0 };
    err = uc_mem_read(uc, r_rdx, &Protocol, sizeof(EFI_GUID));
    VERIFY_UC_OPERATION_NORET(err, "Failed to read protocol GUID");

    DEBUG_MSG("Request to LocateHandleBuffer with GUID %s (%s)",
        guid_to_string(&Protocol), get_guid_friendly_name(Protocol));

    /* return value */
    uint64_t r_rax = EFI_SUCCESS;
    err = uc_reg_write(uc, UC_X86_REG_RAX, &r_rax);
    VERIFY_UC_OPERATION_VOID(err, "Failed to write RAX return value");
}

/*
 * EFI_STATUS(EFIAPI * EFI_LOCATE_PROTOCOL) (IN EFI_GUID *Protocol, IN VOID *Registration, OPTIONAL OUT VOID **Interface)
 */
static void
hook_LocateProtocol(uc_engine *uc, uint64_t address, uint32_t size, void *user_data)
{
    uc_err err = UC_ERR_OK;
    uint64_t ret = EFI_SUCCESS;

    LOG_UC_BACKTRACE(uc, "LocateProtocol()")
    
    uint64_t r_rcx = 0;     /* Protocol */
    uint64_t r_rdx = 0;     /* Registration */
    uint64_t r_r8 = 0;      /* Interface */

    EFI_GUID Protocol = {0};
    /* read Protocol location */
    err = uc_reg_read(uc, UC_X86_REG_RCX, &r_rcx);
    VERIFY_UC_OPERATION_VOID(err, "Failed to read RCX register")
    err = uc_mem_read(uc, r_rcx, &Protocol, sizeof(EFI_GUID));
    VERIFY_UC_OPERATION_NORET(err, "Failed to read protocol GUID")

    DEBUG_MSG("Request to LocateProtocol with GUID %s (%s)",
        guid_to_string(&Protocol), get_guid_friendly_name(Protocol));

    /* read Registration */
    err = uc_reg_read(uc, UC_X86_REG_RDX, &r_rdx);
    VERIFY_UC_OPERATION_VOID(err, "Failed to read RDX register")
    
    /* read Interface */
    err = uc_reg_read(uc, UC_X86_REG_R8, &r_r8);
    VERIFY_UC_OPERATION_VOID(err, "Failed to read R8 register")

    uint64_t t_interface = 0;
    if (locate_protocol(&Protocol, &t_interface) != 0)
    {
        ret = EFI_NOT_FOUND;
        goto out;
    }
    err = uc_mem_write(uc, r_r8, &t_interface, sizeof(t_interface));
    if (err != UC_ERR_OK)
    {
        ret = EFI_NOT_FOUND;
        goto out;
    }
    
    ret = EFI_SUCCESS;
    
out:
    /* return value */
    err = uc_reg_write(uc, UC_X86_REG_RAX, &ret);
    VERIFY_UC_OPERATION_VOID(err, "Failed to write RAX return value");
}

/*
 * EFI_STATUS(EFIAPI * EFI_INSTALL_MULTIPLE_PROTOCOL_INTERFACES) (IN OUT EFI_HANDLE *Handle,...)
 */
static void
hook_InstallMultipleProtocolInterfaces(uc_engine *uc, uint64_t address, uint32_t size, void *user_data)
{
    uc_err err = UC_ERR_OK;
    
    LOG_UC_BACKTRACE(uc, "InstallMultipleProtocolInterfaces()");

    std::vector<std::pair<uint64_t, uint64_t>> protos;
    uint64_t r_rsp = 0;
    uint64_t stack_param;

    /* The 1st protocol GUID is hosted in the RDX register */
    uint64_t r_rdx;
    err = uc_reg_read(uc, UC_X86_REG_RDX, &r_rdx);
    VERIFY_UC_OPERATION_VOID(err, "Failed to read RDX register");

    /* The corresponding interface address is in the R8 register */
    uint64_t r_r8;
    err = uc_reg_read(uc, UC_X86_REG_R8, &r_r8);
    VERIFY_UC_OPERATION_VOID(err, "Failed to read R8 register");

    protos.push_back({ r_rdx, r_r8 });

    /* The 2nd protocol GUID is hosted in the R9 register */
    uint64_t r_r9;
    err = uc_reg_read(uc, UC_X86_REG_R9, &r_r9);
    VERIFY_UC_OPERATION_VOID(err, "Failed to read R9 register");

    /* The 2nd protocol onwards are optional */
    if (r_r9 == 0)
    {
        goto out;
    }
    else
    {
        err = uc_reg_read(uc, UC_X86_REG_RSP, &r_rsp);
        VERIFY_UC_OPERATION_VOID(err, "Failed to read memory at RSP");

        r_rsp += 5 * sizeof(uint64_t);
        uc_mem_read(uc, r_rsp, &stack_param, sizeof(stack_param));

        protos.push_back({ r_r9, stack_param });
    }

    /* Now handle the stack-based parameters */
    r_rsp += sizeof(uint64_t);
    uc_mem_read(uc, r_rsp, &stack_param, sizeof(stack_param));

    while (stack_param)
    {
        uint64_t iface_addr = 0;
        uc_mem_read(uc, r_rsp + sizeof(uint64_t), &iface_addr, sizeof(iface_addr));

        protos.push_back({ stack_param, iface_addr });

        /* Advance to the next protocol GUID */
        r_rsp += 2 * sizeof(uint64_t);
        uc_mem_read(uc, r_rsp, &stack_param, sizeof(stack_param));
    }

out:
    for (const auto& p : protos)
    {
        EFI_GUID Protocol = { 0 };
        err = uc_mem_read(uc, p.first, &Protocol, sizeof(Protocol));
        VERIFY_UC_OPERATION_VOID(err, "Failed to read memory");

        DEBUG_MSG("Installed protocol: %s (%s)",
            guid_to_string(&Protocol), get_guid_friendly_name(Protocol));

        if (add_protocol(&Protocol, p.second) != 0)
        {
            ERROR_MSG("Failed to add Protocol %s\n", guid_to_string(&Protocol));
            continue;
        }
    }

    /* return value */  
    uint64_t r_rax = EFI_SUCCESS;
    err = uc_reg_write(uc, UC_X86_REG_RAX, &r_rax);
    VERIFY_UC_OPERATION_VOID(err, "Failed to write RAX return value");
}

/*
 * EFI_STATUS(EFIAPI * EFI_UNINSTALL_MULTIPLE_PROTOCOL_INTERFACES) (IN EFI_HANDLE Handle,...)
 */
static void
hook_UninstallMultipleProtocolInterfaces(uc_engine *uc, uint64_t address, uint32_t size, void *user_data)
{
    uc_err err = UC_ERR_OK;
    
    LOG_UC_BACKTRACE(uc, "UninstallMultipleProtocolInterfaces()");
    
    /* return value */
    uint64_t r_rax = EFI_SUCCESS;
    err = uc_reg_write(uc, UC_X86_REG_RAX, &r_rax);
    VERIFY_UC_OPERATION_VOID(err, "Failed to write RAX return value");
}

/*
 * EFI_STATUS(EFIAPI * EFI_CALCULATE_CRC32) (IN VOID *Data, IN UINTN DataSize, OUT UINT32 *Crc32)
 */
static void
hook_CalculateCrc32(uc_engine *uc, uint64_t address, uint32_t size, void *user_data)
{
    uc_err err = UC_ERR_OK;
    
    LOG_UC_BACKTRACE(uc, "CalculateCrc32()");
    
    /* return value */
    uint64_t r_rax = EFI_SUCCESS;
    err = uc_reg_write(uc, UC_X86_REG_RAX, &r_rax);
    VERIFY_UC_OPERATION_VOID(err, "Failed to write RAX return value");
}

/*
 * VOID(EFIAPI * EFI_COPY_MEM) (IN VOID *Destination, IN VOID *Source, IN UINTN Length)
 */
static void
hook_CopyMem(uc_engine *uc, uint64_t address, uint32_t size, void *user_data)
{
    uc_err err = UC_ERR_OK;
    
    uint64_t ret = EFI_SUCCESS;

    LOG_UC_BACKTRACE(uc, "CopyMem()");
    
    uint64_t r_rcx = 0;     /* *Destination */
    uint64_t r_rdx = 0;     /* *Source */
    uint64_t r_r8 = 0;      /* Length */

    uint64_t Destination = 0;
    uint64_t Source = 0;
    uint32_t Length = 0;
    
    unsigned char *copyin = NULL;
    
    /* Read Destination paramemter */
    err = uc_reg_read(uc, UC_X86_REG_RCX, &r_rcx);
    if (err != UC_ERR_OK)
    {
        ERROR_MSG("Failed to read RCX register.");
        ret = EFI_OUT_OF_RESOURCES;
        goto out;
    }
    Destination = r_rcx;
    
    /* Read Source parameter */
    err = uc_reg_read(uc, UC_X86_REG_RDX, &r_rdx);
    if (err != UC_ERR_OK)
    {
        ERROR_MSG("Failed to read RDX register.");
        ret = EFI_OUT_OF_RESOURCES;
        goto out;
    }
    Source = r_rdx;
    
    /* read Length */
    err = uc_reg_read(uc, UC_X86_REG_R8, &r_r8);
    if (err != UC_ERR_OK)
    {
        ERROR_MSG("Failed to read RC8 register.");
        ret = EFI_OUT_OF_RESOURCES;
        goto out;
    }
    Length = (uint32_t)r_r8;
    
    /* verify if parameters are ok */
    if (Destination == 0 || Source == 0 || Length == 0)
    {
        ERROR_MSG("Invalidation Destination or Source pointers.");
        ret = EFI_INVALID_PARAMETER;
        goto out;
    }
    
    DEBUG_MSG("Asked to copy 0x%x bytes of mem from 0x%llx to 0x%llx", Length, Source, Destination);
    /* we have no memcpy inside Unicorn API
     * so we need to copyout source and then copyback to destination
     */
    copyin = static_cast<unsigned char *>(malloc(Length));
    if (copyin == NULL)
    {
        ERROR_MSG("Failed to allocate space for copyin.");
        ret = EFI_OUT_OF_RESOURCES;
        goto out;
    }
    err = uc_mem_read(uc, Source, copyin, Length);
    if (err != UC_ERR_OK)
    {
        ERROR_MSG("Failed to read source memory: %s", uc_strerror(err));
        ret = EFI_PROTOCOL_ERROR;
        goto out;
    }
#if 0
    DEBUG_MSG("Source contents to be copied:");
    for (int i = 0; i < Length; i++)
    {
        printf("%02X ", copyin[i]);
    }
    printf("\n");
#endif
    err = uc_mem_write(uc, Destination, copyin, Length);
    if (err != UC_ERR_OK)
    {
        ERROR_MSG("Failed to write destination memory: %s", uc_strerror(err));
        ret = EFI_PROTOCOL_ERROR;
        goto out;
    }

out:
    if (copyin != NULL)
    {
        free(copyin);
    }
    /* write return value */
    err = uc_reg_write(uc, UC_X86_REG_RAX, &ret);
    VERIFY_UC_OPERATION_VOID(err, "Failed to write RAX return value");
}

/*
 * VOID(EFIAPI * EFI_SET_MEM) (IN VOID *Buffer, IN UINTN Size, IN UINT8 Value)
 */
static void
hook_SetMem(uc_engine *uc, uint64_t address, uint32_t size, void *user_data)
{
    uc_err err = UC_ERR_OK;
    
    LOG_UC_BACKTRACE(uc, "SetMem()");
    
    uint64_t r_rcx = 0;     /* *Buffer */
    uint64_t r_rdx = 0;     /* Size */
    uint64_t r_r8 = 0;      /* Value */
    
    /* variables to hold parameters and make it easier to identify what is what */
    uint64_t Buffer = 0;
    uint32_t Size = 0;
    uint8_t Value = 0;
    
    /* Read Buffer parameter */
    err = uc_reg_read(uc, UC_X86_REG_RCX, &r_rcx);
    VERIFY_UC_OPERATION_VOID(err, "Failed to read RCX register");
    Buffer = r_rcx;
    DEBUG_MSG("SetMem Buffer address: 0x%llx", r_rcx);

    /* Read Size parameter */
    err = uc_reg_read(uc, UC_X86_REG_RDX, &r_rdx);
    VERIFY_UC_OPERATION_VOID(err, "Failed to read RDX register");
    Size = (uint32_t)r_rdx;
    if (Size == 0)
    {
        DEBUG_MSG("Request size to SetMem is zero bytes.");
        /* no return value */
        return;
    }
    
    DEBUG_MSG("Requested size to SetMem: 0x%x", (uint32_t)r_rdx);
    
    /* read Value parameter */
    err = uc_reg_read(uc, UC_X86_REG_R8, &r_r8);
    VERIFY_UC_OPERATION_VOID(err, "Failed to read R8 register");
    Value = (uint8_t)r_r8;

    /* finally write whatever value requests into Unicorn memory buffer */
    /* XXX: not exactly the most efficient way :-) */
    for (uint32_t i = 0; i < Size; i++)
    {
        err = uc_mem_write(uc, r_rcx + i, &Value, 1);
        VERIFY_UC_OPERATION_NORET(err, "Failed to write memory");
    }
    
    /* no return value */
}

/*
 * EFI_STATUS(EFIAPI * EFI_CREATE_EVENT_EX) (IN UINT32 Type, IN EFI_TPL NotifyTpl, IN EFI_EVENT_NOTIFY NotifyFunction OPTIONAL, IN CONST VOID *NotifyContext OPTIONAL, IN CONST EFI_GUID *EventGroup OPTIONAL, OUT EFI_EVENT *Event)
 */
static void
hook_CreateEventEx(uc_engine *uc, uint64_t address, uint32_t size, void *user_data)
{
    uc_err err = UC_ERR_OK;
    
    LOG_UC_BACKTRACE(uc, "CreateEventEx()");
    
    /* return value */
    uint64_t r_rax = EFI_SUCCESS;
    err = uc_reg_write(uc, UC_X86_REG_RAX, &r_rax);
    VERIFY_UC_OPERATION_VOID(err, "Failed to write RAX return value");
}
