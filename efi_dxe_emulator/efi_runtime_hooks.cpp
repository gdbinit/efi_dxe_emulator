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
 * Created by fG! on 25/04/16.
 * Copyright © 2016-2019 fG!. All rights reserved.
 * reverser@put.as - https://reverse.put.as
 *
 * efi_runtime_hooks.c
 *
 * Emulated EFI Runtime Services
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

#include "efi_runtime_hooks.h"

#include <stdio.h>
#include <string.h>
#include <wchar.h>

#include "pe_definitions.h"
#include "efi_definitions.h"
#include "logging.h"
#include "config.h"
#include "nvram.h"
#include "string_ops.h"
#include "unicorn_hooks.h"
#include "unicorn_macros.h"
#include "unicorn_utils.h"
#include "mem_utils.h"
#include "guids.h"

extern struct nvram_vars_tailhead g_nvram_vars;

static void hook_GetTime(uc_engine *uc, uint64_t address, uint32_t size, void *user_data);
static void hook_SetTime(uc_engine *uc, uint64_t address, uint32_t size, void *user_data);
static void hook_GetWakeupTime(uc_engine *uc, uint64_t address, uint32_t size, void *user_data);
static void hook_SetWakeupTime(uc_engine *uc, uint64_t address, uint32_t size, void *user_data);
static void hook_SetVirtualAddressMap(uc_engine *uc, uint64_t address, uint32_t size, void *user_data);
static void hook_ConvertPointer(uc_engine *uc, uint64_t address, uint32_t size, void *user_data);
static void hook_GetVariable(uc_engine *uc, uint64_t address, uint32_t size, void *user_data);
static void hook_GetNextVariableName(uc_engine *uc, uint64_t address, uint32_t size, void *user_data);
static void hook_SetVariable(uc_engine *uc, uint64_t address, uint32_t size, void *user_data);
static void hook_GetNextHighMonotonicCount(uc_engine *uc, uint64_t address, uint32_t size, void *user_data);
static void hook_ResetSystem(uc_engine *uc, uint64_t address, uint32_t size, void *user_data);
static void hook_UpdateCapsule(uc_engine *uc, uint64_t address, uint32_t size, void *user_data);
static void hook_QueryCapsuleCapabilities(uc_engine *uc, uint64_t address, uint32_t size, void *user_data);
static void hook_QueryVariableInfo(uc_engine *uc, uint64_t address, uint32_t size, void *user_data);

struct _runtime_hooks
{
    char name[64];
    int offset;
    void *hook;
    uint64_t addr;
};

struct _runtime_hooks runtime_hooks[] = {
    {
        .name = "GetTime",
        .offset = offsetof(EFI_RUNTIME_SERVICES, GetTime),
        .hook = (void*)hook_GetTime
    },
    {
        .name = "SetTime",
        .offset = offsetof(EFI_RUNTIME_SERVICES, SetTime),
        .hook = (void*)hook_SetTime
    },
    {
        .name = "GetWakeupTime",
        .offset = offsetof(EFI_RUNTIME_SERVICES, GetWakeupTime),
        .hook = hook_GetWakeupTime
    },
    {
        .name = "SetWakeupTime",
        .offset = offsetof(EFI_RUNTIME_SERVICES, SetWakeupTime),
        .hook = hook_SetWakeupTime
    },
    {
        .name = "SetVirtualAddressMap",
        .offset = offsetof(EFI_RUNTIME_SERVICES, SetVirtualAddressMap),
        .hook = hook_SetVirtualAddressMap
    },
    {
        .name = "ConvertPointer",
        .offset = offsetof(EFI_RUNTIME_SERVICES, ConvertPointer),
        .hook = hook_ConvertPointer
    },
    {
        .name = "GetVariable",
        .offset = offsetof(EFI_RUNTIME_SERVICES, GetVariable),
        .hook = hook_GetVariable
    },
    {
        .name = "GetNextVariableName",
        .offset = offsetof(EFI_RUNTIME_SERVICES, GetNextVariableName),
        .hook = hook_GetNextVariableName
    },
    {
        .name = "SetVariable",
        .offset = offsetof(EFI_RUNTIME_SERVICES, SetVariable),
        .hook = hook_SetVariable
    },
    {
        .name = "GetNextHighMonotonicCount",
        .offset = offsetof(EFI_RUNTIME_SERVICES, GetNextHighMonotonicCount),
        .hook = hook_GetNextHighMonotonicCount
    },
    {
        .name = "ResetSystem",
        .offset = offsetof(EFI_RUNTIME_SERVICES, ResetSystem),
        .hook = hook_ResetSystem
    },
    {
        .name = "UpdateCapsule",
        .offset = offsetof(EFI_RUNTIME_SERVICES, UpdateCapsule),
        .hook = hook_UpdateCapsule
    },
    {
        .name = "QueryCapsuleCapabilities",
        .offset = offsetof(EFI_RUNTIME_SERVICES, QueryCapsuleCapabilities),
        .hook = hook_QueryCapsuleCapabilities
    },
    {
        .name = "QueryVariableInfo",
        .offset = offsetof(EFI_RUNTIME_SERVICES, QueryVariableInfo),
        .hook = hook_QueryVariableInfo
    }
};

int
install_runtime_services(uc_engine *uc, uint64_t base_addr, size_t *out_count)
{
    uc_err err = UC_ERR_OK;
    
    /* create the RunTime services table */
    EFI_RUNTIME_SERVICES runtime_table = {0};

    int hook_size = HOOK_SIZE;
    
    uint64_t hooks_addr = base_addr + sizeof(EFI_RUNTIME_SERVICES);
    
    size_t array_size = sizeof(runtime_hooks) / sizeof(*runtime_hooks);
    for (int i = 0; i < array_size; i++)
    {
        *(uint64_t*)((char*)&runtime_table + runtime_hooks[i].offset) = (uint64_t)(hooks_addr + hook_size * i);
    }
    
    /* each EFI service is just a return so the call returns cleanly */
    auto ret_bytes = static_cast<unsigned char *>(my_malloc(hook_size * array_size));
    memset(ret_bytes, 0xC3, hook_size * array_size);
    err = uc_mem_write(uc, hooks_addr, ret_bytes, hook_size * array_size);
    /* XXX: will leak ret_bytes but we will exit program anyway */
    VERIFY_UC_OPERATION_RET(err, 1, "Failed to write runtime hooks");

    /* add a Unicorn hook to each service - each hook corresponds to the emulated function */
    for (int i = 0; i < array_size; i++)
    {
        runtime_hooks[i].addr = hooks_addr + hook_size * i;
        add_unicorn_hook(uc, UC_HOOK_CODE, runtime_hooks[i].hook, runtime_hooks[i].addr, runtime_hooks[i].addr);
    }

    err = uc_mem_write(uc, base_addr, (void*)&runtime_table, sizeof(EFI_RUNTIME_SERVICES));
    /* XXX: will leak ret_bytes but we will exit program anyway */
    VERIFY_UC_OPERATION_RET(err, 1, "Failed to write EFI runtime table");
    
    *out_count = array_size;
    
    free(ret_bytes);
    
    return 0;
}

char *
lookup_runtime_services_table(int offset)
{
    size_t array_size = sizeof(runtime_hooks) / sizeof(*runtime_hooks);
    for (int i = 0; i < array_size; i++)
    {
        if (runtime_hooks[i].offset == offset)
        {
            return runtime_hooks[i].name;
        }
    }
    return NULL;
}

uint64_t
lookup_runtime_services_table(std::string_view name)
{
    size_t array_size = sizeof(runtime_hooks) / sizeof(*runtime_hooks);
    for (int i = 0; i < array_size; i++)
    {
        if (name == runtime_hooks[i].name)
        {
            return runtime_hooks[i].addr;
        }
    }
    return 0;
}

/*
 * EFI_STATUS(EFIAPI * EFI_GET_TIME) (OUT EFI_TIME *Time, OUT EFI_TIME_CAPABILITIES *Capabilities OPTIONAL)
 */
static void
hook_GetTime(uc_engine *uc, uint64_t address, uint32_t size, void *user_data)
{
    LOG_UC_BACKTRACE(uc, "GetTime()");
}

/*
 * EFI_STATUS(EFIAPI * EFI_SET_TIME) (IN EFI_TIME *Time)
 */
static void
hook_SetTime(uc_engine *uc, uint64_t address, uint32_t size, void *user_data)
{
    LOG_UC_BACKTRACE(uc, "SetTime()");
}

/*
 * EFI_STATUS(EFIAPI * EFI_GET_WAKEUP_TIME) (OUT BOOLEAN *Enabled, OUT BOOLEAN *Pending, OUT EFI_TIME *Time)
 */
static void
hook_GetWakeupTime(uc_engine *uc, uint64_t address, uint32_t size, void *user_data)
{
    LOG_UC_BACKTRACE(uc, "GetWakeUpTime()");
}

/*
 * EFI_STATUS(EFIAPI * EFI_SET_WAKEUP_TIME) (IN BOOLEAN Enable, IN EFI_TIME *Time OPTIONAL)
 */
static void
hook_SetWakeupTime(uc_engine *uc, uint64_t address, uint32_t size, void *user_data)
{
    LOG_UC_BACKTRACE(uc, "SetWakeUpTime()");
}

/*
 * EFI_STATUS(EFIAPI * EFI_SET_VIRTUAL_ADDRESS_MAP) (IN UINTN MemoryMapSize, IN UINTN DescriptorSize, IN UINT32 DescriptorVersion, IN EFI_MEMORY_DESCRIPTOR *VirtualMap)
 */
static void
hook_SetVirtualAddressMap(uc_engine *uc, uint64_t address, uint32_t size, void *user_data)
{
    LOG_UC_BACKTRACE(uc, "SetVirtualAddressMap()");
}

/*
 * EFI_STATUS(EFIAPI * EFI_CONVERT_POINTER) (IN UINTN DebugDisposition, IN OUT VOID **Address)
 */
static void
hook_ConvertPointer(uc_engine *uc, uint64_t address, uint32_t size, void *user_data)
{
    LOG_UC_BACKTRACE(uc, "ConvertPointer()");
}

/*
 * EFI_STATUS(EFIAPI * EFI_GET_VARIABLE) (IN CHAR16 *VariableName, IN EFI_GUID *VendorGuid, OUT UINT32 *Attributes, OPTIONAL IN OUT UINTN *DataSize, OUT VOID *Data)
 *
 * if DataSize is zero it should return the size of the variable so memory can be allocated for it
 *
 */
static void
hook_GetVariable(uc_engine *uc, uint64_t address, uint32_t size, void *user_data)
{
    uc_err err = UC_ERR_OK;
    uint64_t ret = EFI_SUCCESS;
    
    LOG_UC_BACKTRACE(uc, "GetVariable()");
    
    uint64_t r_rcx = 0;     /* VariableName */
    uint64_t r_rdx = 0;     /* VendorGuid */
    uint64_t r_r8 = 0;      /* Attributes */
    uint64_t r_r9 = 0;      /* DataSize */
    uint64_t r_data = 0;    /* Data */
    
    /* XXX: max 256 wide chars */
    /* we have no idea about the length and it's residing on Unicorn memory */
    CHAR16 VariableName[256+1] = {0};
    EFI_GUID VendorGuid = {0};
    uint32_t Attributes = 0;
    uint32_t DataSize = 0;
    uint64_t Data = 0;

    /* read VariableName location and contents */
    err = uc_reg_read(uc, UC_X86_REG_RCX, &r_rcx);
    VERIFY_UC_OPERATION_VOID(err, "Failed to read RCX register");
    err = uc_mem_read(uc, r_rcx, VariableName, sizeof(VariableName));
    VERIFY_UC_OPERATION_NORET(err, "Failed to read VariableName")

    /* read GUID and contents */
    err = uc_reg_read(uc, UC_X86_REG_RDX, &r_rdx);
    VERIFY_UC_OPERATION_VOID(err, "Failed to read RDX register");
    err = uc_mem_read(uc, r_rdx, &VendorGuid, sizeof(EFI_GUID));
    VERIFY_UC_OPERATION_NORET(err, "Failed to read Vendor GUID")

    /* read Attributes */
    err = uc_reg_read(uc, UC_X86_REG_R8, &r_r8);
    VERIFY_UC_OPERATION_VOID(err, "Failed to read R8 register");
    
    /* read DataSize */
    err = uc_reg_read(uc, UC_X86_REG_R9, &r_r9);
    VERIFY_UC_OPERATION_VOID(err, "Failed to read R9 register");
    err = uc_mem_read(uc, r_r9, &DataSize, sizeof(DataSize));
    VERIFY_UC_OPERATION_NORET(err, "Failed to read DataSize")
    
    DEBUG_MSG("GetVariable() DataSize is 0x%x", DataSize)
    
    /* read Data pointer */
    /* value was passed via stack */
    uint64_t r_rsp = 0;
    err = uc_reg_read(uc, UC_X86_REG_RSP, &r_rsp);
    VERIFY_UC_OPERATION_VOID(err, "Failed to read RSP register");
    /* set the stack location we can read the pointer from */
    r_rsp += 0x28;
    err = uc_mem_read(uc, r_rsp, &Data, sizeof(Data));
    VERIFY_UC_OPERATION_NORET(err, "Failed to read Data")
    
    DEBUG_MSG("Data address 0x%llx 0x%llx", r_rsp, Data)

    /* copy the VariableName from Unicorn memory */
    uint32_t length = StrLen(VariableName);
    VariableName[length*2+2] = L'\0';
    char ascii_var[256] = {0};
    UnicodeStrToAsciiStr(VariableName, ascii_var);
    DEBUG_MSG("Request GetVariable to: %s", ascii_var);
    
    EFI_GUID *guid = &VendorGuid;
    OUTPUT_MSG("%s (%s)", guid_to_string(guid), get_guid_friendly_name(*guid));
    
    uint32_t content_size = 0;
    uint8_t* var_buf = NULL;

    /*
     * if DataSize is zero it usually means that caller wants to know the length of the Data
     * to be returned
     */
    if (DataSize == 0)
    {
        lookup_nvram_var(VariableName, &VendorGuid, &content_size, NULL);
        /* set the data Size */
        DataSize = content_size;
        if (uc_mem_write(uc, r_r9, &DataSize, sizeof(DataSize)) != UC_ERR_OK)
        {
            ERROR_MSG("Error writing DataSize.");
            ret = EFI_UNSUPPORTED;
            goto out;
        }

        /* return value */
        ret = EFI_BUFFER_TOO_SMALL;
        goto out;
    }
    /*
     * here we return the real data
     */
    else
    {
        lookup_nvram_var(VariableName, &VendorGuid, &content_size, &var_buf);
#if 0
        DEBUG_MSG("Variable contents retrieved:");
        for (int i = 0; i < content_size; i++)
        {
            printf("%02X ", var_buf[i]);
        }
        printf("\n");
#endif
        /* We need to set Attributes (ignore for now), DataSize, and Data */
        
        /* write contents into Unicorn memory */
        if (uc_mem_write(uc, Data, var_buf, content_size) != UC_ERR_OK)
        {
            ERROR_MSG("Error writing Data.");
            ret = EFI_UNSUPPORTED;
            goto out;
        }
        /* set the data Size */
        DataSize = content_size;
        if (uc_mem_write(uc, r_r9, &DataSize, sizeof(DataSize)) != UC_ERR_OK)
        {
            ERROR_MSG("Error writing DataSize.");
            ret = EFI_UNSUPPORTED;
            goto out;
        }
        ret = EFI_SUCCESS;
        goto out;
    }
    
out:
    if (var_buf)
    {
        free(var_buf);
    }

    /* return value */
    err = uc_reg_write(uc, UC_X86_REG_RAX, &ret);
    VERIFY_UC_OPERATION_VOID(err, "Failed to write RAX return value");
}

/*
 * EFI_STATUS(EFIAPI * EFI_GET_NEXT_VARIABLE_NAME) (IN OUT UINTN *VariableNameSize, IN OUT CHAR16 *VariableName, IN OUT EFI_GUID *VendorGuid)
 */
static void
hook_GetNextVariableName(uc_engine *uc, uint64_t address, uint32_t size, void *user_data)
{
    uint64_t ret = EFI_SUCCESS;
    uc_err err = UC_ERR_OK;

    LOG_UC_BACKTRACE(uc, "GetNextVariableName()");
    
    uint64_t r_rcx = 0;     /* VariableNameSize */
    uint64_t r_rdx = 0;     /* VariableName */
    uint64_t r_r8 = 0;      /* VendorGuid */
    CHAR16 *VariableName = NULL;

    /* read arguments from Unicorn registers */
    if ( (err = uc_reg_read(uc, UC_X86_REG_RCX, &r_rcx)) != UC_ERR_OK)
    {
        ERROR_MSG("Failed to retrieve RCX register: %s.", uc_strerror(err));
        ret = EFI_INVALID_PARAMETER;
        goto out;
    }
    
    if ( (err = uc_reg_read(uc, UC_X86_REG_RDX, &r_rdx)) != UC_ERR_OK)
    {
        ERROR_MSG("Failed to retrieve RDX register: %s.", uc_strerror(err));
        ret = EFI_INVALID_PARAMETER;
        goto out;
    }

    if ( (err = uc_reg_read(uc, UC_X86_REG_R8, &r_r8)) != UC_ERR_OK)
    {
        ERROR_MSG("Failed to retrieve R8 register: %s.", uc_strerror(err));
        ret = EFI_INVALID_PARAMETER;
        goto out;
    }
    /* verify if any argument is NULL */
    if (r_rcx == 0 || r_rdx == 0 || r_r8 == 0)
    {
        ERROR_MSG("NULL pointers in arguments.");
        ret = EFI_INVALID_PARAMETER;
        goto out;
    }
        
    CHAR16 ShortVariableName = 0;
    err = uc_mem_read(uc, r_rdx, &ShortVariableName, sizeof(CHAR16));
    VERIFY_UC_OPERATION_VOID(err, "Failed to read RDX register");
    /* if VariableName is empty just retrieve the first variable we have */
    if (ShortVariableName == 0)
    {
        struct nvram_variables *entry = NULL;
        entry = TAILQ_FIRST(&g_nvram_vars);
        uint32_t length = entry->name_size;
        err = uc_mem_write(uc, r_rdx, entry->name, entry->name_size);
        VERIFY_UC_OPERATION_NORET(err, "Failed to write to Unicorn memory")
        err = uc_mem_write(uc, r_r8, &entry->guid, sizeof(EFI_GUID));
        VERIFY_UC_OPERATION_NORET(err, "Failed to write to Unicorn memory")
        err = uc_mem_write(uc, r_rcx, &length, sizeof(length));
        VERIFY_UC_OPERATION_NORET(err, "Failed to write to Unicorn memory")
    }
    /* when there's a variable we need to return the next one */
    else
    {
        uint32_t VariableNameSize = 0;
        err = uc_mem_read(uc, r_rcx, &VariableNameSize, sizeof(VariableNameSize));
        VERIFY_UC_OPERATION_NORET(err, "Failed to read VariableNameSize")
        VariableName = static_cast<CHAR16 *>(my_malloc(VariableNameSize));
        err = uc_mem_read(uc, r_rdx, VariableName, VariableNameSize);
        VERIFY_UC_OPERATION_NORET(err, "Failed to read VariableName")
        EFI_GUID VendorGuid = {0};
        err = uc_mem_read(uc, r_r8, &VendorGuid, sizeof(EFI_GUID));
        VERIFY_UC_OPERATION_NORET(err, "Failed to read Vendor GUID")
//        EFI_GUID *guid = &VendorGuid;
//        OUTPUT_MSG("-[ IN GUID: %08X-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X ]-",
//                   guid->Data1, guid->Data2, guid->Data3,
//                   guid->Data4[0], guid->Data4[1], guid->Data4[2], guid->Data4[3],
//                   guid->Data4[4], guid->Data4[5], guid->Data4[6], guid->Data4[7]);
//        
        print_unicode_string(VariableName);

        struct nvram_variables *entry = NULL;
        /* first try to see if the variable exists */
        int found = 0;
        TAILQ_FOREACH(entry, &g_nvram_vars, entries)
        {
            if (memcmp(VariableName, entry->name, entry->name_size) == 0)
            {
                found = 1;
                break;
            }
        }
        if (found == 0)
        {
            DEBUG_MSG("Variable not found.");
            ret = EFI_NOT_FOUND;
            goto out;
        }
        
        /* if the variable exists return the next one */
        TAILQ_FOREACH(entry, &g_nvram_vars, entries)
        {
            if (memcmp(&entry->guid, &VendorGuid, sizeof(EFI_GUID)) == 0 &&
                memcmp(VariableName, entry->name, entry->name_size) == 0)
            {
                struct nvram_variables *next_entry = NULL;
                next_entry = TAILQ_NEXT(entry, entries);

                if (next_entry == NULL)
                {
                    DEBUG_MSG("Variable not found.");
                    ret = EFI_NOT_FOUND;
                    goto out;
                }
                uint32_t length = next_entry->name_size;
                err = uc_mem_write(uc, r_rdx, next_entry->name, next_entry->name_size);
                VERIFY_UC_OPERATION_NORET(err, "Failed to write to Unicorn memory")
                err = uc_mem_write(uc, r_r8, &next_entry->guid, sizeof(EFI_GUID));
                VERIFY_UC_OPERATION_NORET(err, "Failed to write to Unicorn memory")
                err = uc_mem_write(uc, r_rcx, &length, sizeof(length));
                VERIFY_UC_OPERATION_NORET(err, "Failed to write to Unicorn memory")
                break;
            }
        }
    }
    
out:
    if (VariableName != NULL)
    {
        free(VariableName);
    }
    /* return value */
    err = uc_reg_write(uc, UC_X86_REG_RAX, &ret);
    VERIFY_UC_OPERATION_VOID(err, "Failed to write RAX return value");
}

/*
 * EFI_STATUS(EFIAPI * EFI_SET_VARIABLE) (IN CHAR16 *VariableName, IN EFI_GUID *VendorGuid, IN UINT32 Attributes, IN UINTN DataSize, IN VOID *Data)
 */
static void
hook_SetVariable(uc_engine *uc, uint64_t address, uint32_t size, void *user_data)
{
    uc_err err = UC_ERR_OK;
    
    LOG_UC_BACKTRACE(uc, "SetVariable()");
    
    uint64_t r_rcx = 0;     /* VariableName */
    uint64_t r_rdx = 0;     /* VendorGuid */
    uint64_t r_r8 = 0;      /* Attributes */
    uint64_t r_r9 = 0;      /* DataSize */
    uint64_t r_data = 0;    /* Data */
    /* read VariableName location */
    err = uc_reg_read(uc, UC_X86_REG_RCX, &r_rcx);
    VERIFY_UC_OPERATION_VOID(err, "Failed to read RCX register");
    /* copy the VariableName from Unicorn memory */
    /* XXX: max 256 wide chars */
    CHAR16 var_name[256+1] = {0};
    CHAR16 *var_name_ptr = var_name;
    err = uc_mem_read(uc, r_rcx, var_name, sizeof(var_name));
    VERIFY_UC_OPERATION_NORET(err, "Failed to read VariableName")
    uint32_t length = StrLen(var_name_ptr);
    var_name[length*2+2] = L'\0';
    char ascii_variable[256] = {0};
    UnicodeStrToAsciiStr(var_name_ptr, ascii_variable);
    DEBUG_MSG("Request SetVariable to: %s", ascii_variable);
    
    /* read GUID */
    err = uc_reg_read(uc, UC_X86_REG_RDX, &r_rdx);
    VERIFY_UC_OPERATION_VOID(err, "Failed to read RDX register");
    EFI_GUID VendorGuid = {0};
    err = uc_mem_read(uc, r_rdx, &VendorGuid, sizeof(EFI_GUID));
    VERIFY_UC_OPERATION_NORET(err, "Failed to read Vendor GUID")
    EFI_GUID *guid = &VendorGuid;
    OUTPUT_MSG("%s (%s)", guid_to_string(guid), get_guid_friendly_name(*guid));

    /* read attributes */
    err = uc_reg_read(uc, UC_X86_REG_R8, &r_r8);
    VERIFY_UC_OPERATION_VOID(err, "Failed to read R8 register");

    /* read data length */
    err = uc_reg_read(uc, UC_X86_REG_R9, &r_r9);
    VERIFY_UC_OPERATION_VOID(err, "Failed to read R9 register");

    /* read data */
    uint64_t r_rsp = 0;
    err = uc_reg_read(uc, UC_X86_REG_RSP, &r_rsp);
    VERIFY_UC_OPERATION_VOID(err, "Failed to read RSP register");

    r_rsp += 5 * sizeof(uint64_t);
    uc_mem_read(uc, r_rsp, &r_data, sizeof(r_data));

    std::vector<std::byte> var_data(r_r9);
    uc_mem_read(uc, r_data, var_data.data(), r_r9);

    auto new_entry = static_cast<struct nvram_variables*>(my_malloc(sizeof(struct nvram_variables)));
    memcpy(&new_entry->guid, guid, sizeof(EFI_GUID));
    if (length * 2 + 2 <= sizeof(new_entry->name))
    {
        memcpy(new_entry->name, var_name_ptr, length * 2 + 2);
    }
    else
    {
        memcpy(new_entry->name, var_name_ptr, sizeof(new_entry->name));
    }
    new_entry->name_size = length * 2 + 2;
    new_entry->data_size = r_r9;
    new_entry->data = static_cast<uint8_t*>(my_malloc(new_entry->data_size));
    memcpy(new_entry->data, var_data.data(), new_entry->data_size);
    TAILQ_INSERT_TAIL(&g_nvram_vars, new_entry, entries);

    /* return value */
    uint64_t r_rax = EFI_SUCCESS;
    err = uc_reg_write(uc, UC_X86_REG_RAX, &r_rax);
    VERIFY_UC_OPERATION_VOID(err, "Failed to write RAX return value");
}

extern uint64_t gCurrentMonotonicCount;

/*
 * EFI_STATUS(EFIAPI * EFI_GET_NEXT_HIGH_MONO_COUNT) (OUT UINT32 *HighCount)
 */
static void
hook_GetNextHighMonotonicCount(uc_engine *uc, uint64_t address, uint32_t size, void *user_data)
{
    uint64_t ret = EFI_SUCCESS;
    uc_err err = UC_ERR_OK;
    
    LOG_UC_BACKTRACE(uc, "GetNextHighMonotonicCount()");
    
    uint64_t r_rcx = 0;     /* Count */
    err = uc_reg_read(uc, UC_X86_REG_RCX, &r_rcx);
    if (err != UC_ERR_OK)
    {
        DEBUG_MSG("Failed to read RCX register: %s", uc_strerror(err));
        ret = EFI_INVALID_PARAMETER;
        goto out;
    }
    /* test if HighCount ptr is NULL */
    if (r_rcx == 0)
    {
        ret = EFI_INVALID_PARAMETER;
        goto out;
    }
    
    gCurrentMonotonicCount += 0x0000000100000000;

    /* XXX: is this correct??? */
    uint32_t HighCount = (uint32_t)((gCurrentMonotonicCount >> 32) & 0xFFFFFFFF);
    
    if (uc_mem_write(uc, r_rcx, &HighCount, sizeof(HighCount)) != UC_ERR_OK)
    {
        ERROR_MSG("Failed to write register.");
        ret = EFI_INVALID_PARAMETER;
        goto out;
    }
out:
    /* return value */
    err = uc_reg_write(uc, UC_X86_REG_RAX, &ret);
    VERIFY_UC_OPERATION_VOID(err, "Failed to write RAX return value");
}

/*
 * VOID(EFIAPI * EFI_RESET_SYSTEM) (IN EFI_RESET_TYPE ResetType, IN EFI_STATUS ResetStatus, IN UINTN DataSize, IN VOID *ResetData OPTIONAL)
 */
static void
hook_ResetSystem(uc_engine *uc, uint64_t address, uint32_t size, void *user_data)
{
    LOG_UC_BACKTRACE(uc, "ResetSystem()");
}

/*
 * EFI_STATUS(EFIAPI * EFI_UPDATE_CAPSULE) (IN EFI_CAPSULE_HEADER **CapsuleHeaderArray, IN UINTN CapsuleCount, IN EFI_PHYSICAL_ADDRESS ScatterGatherList OPTIONAL)
 */
static void
hook_UpdateCapsule(uc_engine *uc, uint64_t address, uint32_t size, void *user_data)
{
    LOG_UC_BACKTRACE(uc, "UpdateCapsule()");
}

/*
 * EFI_STATUS(EFIAPI * EFI_QUERY_CAPSULE_CAPABILITIES) (IN EFI_CAPSULE_HEADER **CapsuleHeaderArray, IN UINTN CapsuleCount, OUT UINT64 *MaximumCapsuleSize, OUT EFI_RESET_TYPE *ResetType)
 */
static void
hook_QueryCapsuleCapabilities(uc_engine *uc, uint64_t address, uint32_t size, void *user_data)
{
    LOG_UC_BACKTRACE(uc, "QueryCapsuleCapabilities()");
}

/*
 * EFI_STATUS(EFIAPI * EFI_QUERY_VARIABLE_INFO) (IN UINT32 Attributes, OUT UINT64 *MaximumVariableStorageSize, OUT UINT64 *RemainingVariableStorageSize, OUT UINT64 *MaximumVariableSize)
 */
static void
hook_QueryVariableInfo(uc_engine *uc, uint64_t address, uint32_t size, void *user_data)
{
    LOG_UC_BACKTRACE(uc, "QueryVariableInfo()");
}
