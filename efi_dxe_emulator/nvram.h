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
 * nvram.h
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

#pragma once

#include <stdint.h>
#include <sys/queue.h>
#include <unicorn/unicorn.h>

#include "efi_definitions.h"

void register_nvram_cmds(uc_engine *uc);
int load_nvram(char *nvram_file);
int lookup_nvram_var(CHAR16 *var_name, EFI_GUID *guid, uint32_t *content_size, unsigned char **out_buf);

struct nvram_variables
{
    CHAR16 name[256];
    EFI_GUID guid;
    uint8_t *data;
    TAILQ_ENTRY(nvram_variables) entries;
    uint32_t data_size;
    uint32_t name_size;
};

TAILQ_HEAD(nvram_vars_tailhead, nvram_variables);

#pragma pack(push, 1)

#define NVRAM_VSS_STORE_SIGNATURE            0x53535624 // $VSS
#define NVRAM_APPLE_SVS_STORE_SIGNATURE      0x53565324 // $SVS
#define NVRAM_APPLE_FSYS_STORE_SIGNATURE     0x73797346 // Fsys
#define NVRAM_APPLE_GAID_STORE_SIGNATURE     0x64696147 // Gaid
#define NVRAM_VSS_VARIABLE_START_ID          0x55AA
#define NVRAM_NVAR_ENTRY_SIGNATURE           0x5241564e // NVAR

// Variable store header flags
#define NVRAM_VSS_VARIABLE_STORE_FORMATTED  0x5a
#define NVRAM_VSS_VARIABLE_STORE_HEALTHY    0xfe

// Variable store status
#define NVRAM_VSS_VARIABLE_STORE_STATUS_RAW     0
#define NVRAM_VSS_VARIABLE_STORE_STATUS_VALID   1
#define NVRAM_VSS_VARIABLE_STORE_STATUS_INVALID 2
#define NVRAM_VSS_VARIABLE_STORE_STATUS_UNKNOWN 3

// Variable store header
typedef struct VSS_VARIABLE_STORE_HEADER_ {
    UINT32  Signature; // $VSS signature
    UINT32  Size;      // Size of variable store, including store header
    UINT8   Format;    // Store format state
    UINT8   State;     // Store health state
    UINT16  Unknown;   // Used in Apple $SVS varstores
    UINT32  : 32;
} VSS_VARIABLE_STORE_HEADER;

// Normal variable header
typedef struct VSS_VARIABLE_HEADER_ {
    UINT16    StartId;    // Variable start marker AA55
    UINT8     State;      // Variable state
    UINT8     : 8;
    UINT32    Attributes; // Variable attributes
    UINT32    NameSize;   // Size of variable name, stored as null-terminated UCS2 string
    UINT32    DataSize;   // Size of variable data without header and name
    EFI_GUID  VendorGuid; // Variable vendor GUID
} VSS_VARIABLE_HEADER;

// Apple variation of normal variable header, with one new field
typedef struct VSS_APPLE_VARIABLE_HEADER_ {
    UINT16    StartId;    // Variable start marker AA55
    UINT8     State;      // Variable state
    UINT8     : 8;
    UINT32    Attributes; // Variable attributes
    UINT32    NameSize;   // Size of variable name, stored as null-terminated UCS2 string
    UINT32    DataSize;   // Size of variable data without header and name
    EFI_GUID  VendorGuid; // Variable vendor GUID
    UINT32    DataCrc32;  // CRC32 of the data
} VSS_APPLE_VARIABLE_HEADER;

typedef struct _NVAR_ENTRY_HEADER {
    UINT32 Signature;      // NVAR
    UINT16 Size;           // Size of the entry including header
    UINT32 Next : 24;      // Offset to the next entry in a list, or empty if the latest in the list
    UINT32 Attributes : 8; // Attributes
} NVAR_ENTRY_HEADER;

#define NVRAM_NVAR_ENTRY_RUNTIME          0x01
#define NVRAM_NVAR_ENTRY_ASCII_NAME       0x02
#define NVRAM_NVAR_ENTRY_GUID             0x04
#define NVRAM_NVAR_ENTRY_DATA_ONLY        0x08
#define NVRAM_NVAR_ENTRY_EXT_HEADER       0x10
#define NVRAM_NVAR_ENTRY_HW_ERROR_RECORD  0x20 
#define NVRAM_NVAR_ENTRY_AUTH_WRITE       0x40
#define NVRAM_NVAR_ENTRY_VALID            0x80
#define NVRAM_NVAR_ENTRY_EXT_CHECKSUM      0x01
#define NVRAM_NVAR_ENTRY_EXT_AUTH_WRITE    0x10
#define NVRAM_NVAR_ENTRY_EXT_TIME_BASED    0x20
#define NVRAM_NVAR_ENTRY_EXT_UNKNOWN_MASK  0xCE

// VSS variable states
#define NVRAM_VSS_VARIABLE_IN_DELETED_TRANSITION     0xfe  // Variable is in obsolete transistion
#define NVRAM_VSS_VARIABLE_DELETED                   0xfd  // Variable is obsolete
#define NVRAM_VSS_VARIABLE_HEADER_VALID              0x7f  // Variable has valid header
#define NVRAM_VSS_VARIABLE_ADDED                     0x3f  // Variable has been completely added
#define NVRAM_VSS_IS_VARIABLE_STATE(_c, _Mask)  (BOOLEAN) (((~_c) & (~_Mask)) != 0)

// VSS variable attributes
#define NVRAM_VSS_VARIABLE_NON_VOLATILE                          0x00000001
#define NVRAM_VSS_VARIABLE_BOOTSERVICE_ACCESS                    0x00000002
#define NVRAM_VSS_VARIABLE_RUNTIME_ACCESS                        0x00000004
#define NVRAM_VSS_VARIABLE_HARDWARE_ERROR_RECORD                 0x00000008
#define NVRAM_VSS_VARIABLE_AUTHENTICATED_WRITE_ACCESS            0x00000010
#define NVRAM_VSS_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS 0x00000020
#define NVRAM_VSS_VARIABLE_APPEND_WRITE                          0x00000040
#define NVRAM_VSS_VARIABLE_APPLE_DATA_CHECKSUM                   0x80000000
#define NVRAM_VSS_VARIABLE_UNKNOWN_MASK                          0x7FFFFF80

//
// Apple Fsys store
//

typedef struct APPLE_FSYS_STORE_HEADER_ {
    UINT32  Signature;  // Fsys or Gaid signature
    UINT8   Unknown0;   // Still unknown
    UINT32  Unknown1;   // Still unknown
    UINT16  Size;       // Size of variable store
} APPLE_FSYS_STORE_HEADER;

#pragma pack(pop)