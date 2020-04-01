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
 * nvram.c
 *
 * Functions related to EFI NVRAM
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

#include "nvram.h"

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <unistd.h>
#include <sys/stat.h>
#include <mman/sys/mman.h>
#include <fcntl.h>
#include <string>
#include <memory>

#include "logging.h"
#include "config.h"
#include "efi_definitions.h"
#include "string_ops.h"
#include "cmds.h"
#include "mem_utils.h"
#include "guids.h"
#include <iomanip>
#include <sstream>

uint8_t *g_nvram_buf;
size_t g_nvram_buf_size;

struct nvram_vars_tailhead g_nvram_vars = TAILQ_HEAD_INITIALIZER(g_nvram_vars);

static int dump_nvram_cmd(const char *exp, uc_engine *uc);
static int edit_variable_cmd(const char* exp, uc_engine* uc);
static void dump_nvram_vars(const std::string& var_name);
static void retrieve_nvram_vars(void);
static int parse_nvram(uint8_t *buf, size_t buf_size);

#pragma region Functions to register the commands

void
register_nvram_cmds(uc_engine *uc)
{
    add_user_cmd("nvram", NULL, dump_nvram_cmd, "Dump NVRAM contents.\n\nnvram", uc);
    add_user_cmd("ev", NULL, edit_variable_cmd, "Edit NVRAM variable.\n\nnvram", uc);
}

#pragma endregion

#pragma region Commands functions

static int
dump_nvram_cmd(const char *exp, uc_engine *uc)
{
    auto cmd_tokens = tokenize(exp);
    _ASSERT(cmd_tokens.at(0) == "nvram");

    std::string var_name;
    try
    {
        var_name = cmd_tokens.at(1);
    }
    catch (const std::out_of_range&)
    {
        ; // Nothing
    }

    dump_nvram_vars(var_name);
    return 0;
}

static int
edit_variable_cmd(const char* exp, uc_engine* uc)
{
    auto cmd_tokens = tokenize(exp);
    _ASSERT(cmd_tokens.at(0) == "ev");
    
    std::wstring var_name;
    try
    {
        var_name = to_wstring(cmd_tokens.at(1));
    }
    catch (const std::out_of_range&)
    {
        WARNING_MSG("No variable was specified");
        return 0;
    }

    uint32_t var_size = 0;
    unsigned char* var_data = nullptr;
    auto var = lookup_nvram_var(var_name.c_str(), nullptr, &var_size, &var_data);
    if (!var)
    {
        ERROR_MSG("Variable %S not found", var_name.c_str());
        return 0;
    }

    auto tmpname = std::tmpnam(nullptr);
    auto tmpfile = fopen(tmpname, "wb");
    fwrite(var_data, 1, var_size, tmpfile);
    fclose(tmpfile);

    // Run hex editor
    std::stringstream ss;
    ss << std::quoted(g_config.hex_editor);
    ss << " ";
    ss << tmpname;

    STARTUPINFO si{};
    PROCESS_INFORMATION pi{};
    BOOL rc = CreateProcessA(
        nullptr,
        ss.str().data(),
        nullptr,
        nullptr,
        FALSE,
        0,
        nullptr,
        nullptr,
        &si,
        &pi);
    WaitForSingleObject(pi.hProcess, INFINITE);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    // Re-load the variable.
    tmpfile = fopen(tmpname, "rb");
    fread(var_data, 1, var_size, tmpfile);
    fclose(tmpfile);

    var->data = var_data;

    return 0;
}

#pragma endregion

#pragma region Other functions

int
load_nvram(char *nvram_file)
{
    int fd = open(nvram_file, O_RDONLY);
    if (fd < 0)
    {
        return -1;
    }

    struct stat stat_buf = {0};
    if (fstat(fd, &stat_buf) < 0)
    {
        ERROR_MSG("Failed to fstat nvram file.");
        close(fd);
        return -1;
    }
    
    g_nvram_buf_size = stat_buf.st_size;
    if ((g_nvram_buf = static_cast<uint8_t *>(mmap(0, g_nvram_buf_size, PROT_READ, MAP_SHARED, fd, 0))) == MAP_FAILED)
    {
        ERROR_MSG("Failed to mmap nvram file.");
        close(fd);
        return -1;
    }
    close(fd);

    parse_nvram(g_nvram_buf, g_nvram_buf_size);
    retrieve_nvram_vars();
    
    return 0;
}

int
dump_vss_store(uint8_t *store_buf, uint32_t store_size)
{
    uint8_t *store_ptr = store_buf;
    while (store_ptr < store_buf + store_size)
    {
        VSS_VARIABLE_HEADER *var_header = (VSS_VARIABLE_HEADER*)store_ptr;
        if (var_header->StartId == NVRAM_VSS_VARIABLE_START_ID)
        {
            if (var_header->State == NVRAM_VSS_VARIABLE_HEADER_VALID || var_header->State == NVRAM_VSS_VARIABLE_ADDED)
            {
                DEBUG_MSG("Found variable with state %d!", var_header->State);
                EFI_GUID *guid = &var_header->VendorGuid;
                OUTPUT_MSG("%08X-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X",
                           guid->Data1, guid->Data2, guid->Data3,
                           guid->Data4[0], guid->Data4[1], guid->Data4[2], guid->Data4[3],
                           guid->Data4[4], guid->Data4[5], guid->Data4[6], guid->Data4[7]);
                DEBUG_MSG("Data size: 0x%x Name size: 0x%x Header size: 0x%lx", var_header->DataSize, var_header->NameSize, sizeof(VSS_VARIABLE_HEADER));
                printf("Variable name: ");
                char *name_ptr = (char*)var_header + sizeof(VSS_VARIABLE_HEADER);
                for (int i = 0; i < var_header->NameSize; i++)
                {
                    if (name_ptr[i] != 0x0)
                    {
                        printf("%c", name_ptr[i]);
                    }
                }
                printf("\n");
                char *data_ptr = (char*)var_header + sizeof(VSS_VARIABLE_HEADER) + var_header->NameSize;
                for (int i = 0; i < var_header->DataSize; i++)
                {
                    printf("%02x ", (unsigned char)data_ptr[i]);
                }
                printf("\n");
            }
            store_ptr += var_header->DataSize + var_header->NameSize + sizeof(VSS_VARIABLE_HEADER);
        }
        else
        {
            store_ptr += 1;
        }
    }
    return 0;
}

static int
parse_nvram(uint8_t *buf, size_t buf_size)
{
    uint8_t *buf_ptr = buf;
    size_t cur_pos = 0;
    
    while (cur_pos < buf_size)
    {
        VSS_VARIABLE_STORE_HEADER *vss_header = (VSS_VARIABLE_STORE_HEADER*)buf_ptr;
        switch (vss_header->Signature) {
            case NVRAM_VSS_STORE_SIGNATURE:
            {
                DEBUG_MSG("VSS variable store at 0x%lx.", cur_pos);
//                dump_vss_store(buf_ptr + sizeof(VSS_VARIABLE_STORE_HEADER), vss_header->Size - sizeof(VSS_VARIABLE_STORE_HEADER));
                buf_ptr += vss_header->Size;
                cur_pos += vss_header->Size;
                
                break;
            }
            case NVRAM_APPLE_SVS_STORE_SIGNATURE:
            {
                DEBUG_MSG("SVS variable store at 0x%lx.", cur_pos);
                dump_vss_store(buf_ptr + sizeof(VSS_VARIABLE_STORE_HEADER), vss_header->Size - sizeof(VSS_VARIABLE_STORE_HEADER));
                buf_ptr += vss_header->Size;
                cur_pos += vss_header->Size;
                break;
            }
            default:
            {
                buf_ptr += 1;
                cur_pos += 1;
                break;
            }
        }
        
    }
    return 0;
}

int
find_vss_var(uint8_t *store_buf, uint32_t store_size, CHAR16 *var_name, EFI_GUID *guid, uint32_t *content_size, unsigned char **out_buf)
{
    uint8_t *store_ptr = store_buf;
    while (store_ptr < store_buf + store_size)
    {
        VSS_VARIABLE_HEADER *var_header = (VSS_VARIABLE_HEADER*)store_ptr;
        if (var_header->StartId == NVRAM_VSS_VARIABLE_START_ID)
        {
            if (var_header->State == NVRAM_VSS_VARIABLE_HEADER_VALID || var_header->State == NVRAM_VSS_VARIABLE_ADDED)
            {
                EFI_GUID *header_guid = &var_header->VendorGuid;
                CHAR16 *name_ptr = (CHAR16*)((char*)var_header + sizeof(VSS_VARIABLE_HEADER));
                if (memcmp(guid, header_guid, sizeof(EFI_GUID)) == 0 &&
                    memcmp(var_name, name_ptr, var_header->NameSize) == 0)
                {
                    DEBUG_MSG("Found variable!");
                    *content_size = var_header->DataSize;
                    if (out_buf != NULL)
                    {
                        *out_buf = static_cast<unsigned char *>(my_malloc(var_header->DataSize));
                        memcpy(*out_buf, (char*)var_header + sizeof(VSS_VARIABLE_HEADER) + var_header->NameSize, var_header->DataSize);
                    }
                    break;
                }
            }
            store_ptr += var_header->DataSize + var_header->NameSize + sizeof(VSS_VARIABLE_HEADER);
        }
        else
        {
            store_ptr += 1;
        }
    }
    return 0;
}

struct nvram_variables *
lookup_nvram_var(const CHAR16 *var_name, EFI_GUID *guid, uint32_t *content_size, unsigned char **out_buf)
{
    struct nvram_variables* entry = NULL;
    TAILQ_FOREACH(entry, &g_nvram_vars, entries)
    {
        if (wcsncmp(entry->name, var_name, entry->name_size) == 0)
        {
            DEBUG_MSG("Found variable!");
            *out_buf = static_cast<unsigned char*>(my_malloc(entry->data_size));
            memcpy(*out_buf, entry->data, entry->data_size);
            *content_size = entry->data_size;
            break;
        }
    }
    return entry;
}

static void
dump_nvram_vars(const std::string& var_name)
{
    OUTPUT_MSG("\n-[ NVRAM variables dump ]---------------------");
    struct nvram_variables *entry = NULL;
    TAILQ_FOREACH(entry, &g_nvram_vars, entries)
    {
        uint32_t length = StrLen(entry->name);
        auto c_string = static_cast<char *>(my_malloc(length+2));
        UnicodeStrToAsciiStr(entry->name, c_string);
        bool include = var_name.empty() || (var_name == c_string);
        if (!include) goto next;
        OUTPUT_MSG("\n-[ Variable: %s ]-", c_string);
        EFI_GUID *guid = &entry->guid;
        OUTPUT_MSG("-[ GUID: %s ]-", guid_to_string(guid));
        /* output data in hex and characters if possible */
        int i = 0;
        int x = 0;
        int z = 0;
        int linelength = 0;
        OUTPUT_MSG("-[ Contents ]-");
        while (i < entry->data_size)
        {
            linelength = (entry->data_size -i) <= 16 ? entry->data_size - i : 16;
            z = i;
            for (x = 0; x < linelength; x++)
            {
                fprintf(stdout, "%02X ", entry->data[z++]);
            }
            // make it always 16 columns, this could be prettier :P
            for (x = linelength; x < 16; x++)
            {
                fprintf(stdout, "   ");
            }
            z = i;
            // try to print ascii
            fprintf(stdout, "|");
            for (x = 0; x < linelength; x++)
            {
                fprintf(stdout, "%c", isascii(entry->data[z]) && isprint(entry->data[z]) ? entry->data[z] : '.');
                z++;
            }
            i += 16;
            fprintf(stdout, "|\n");
        }
    next:
        free(c_string);
    }
    OUTPUT_MSG("\n-[ End NVRAM variables dump ]---------------------");
    return;
}

static void
retrieve_nvram_vars(void)
{
    TAILQ_INIT(&g_nvram_vars);
    
    uint8_t *buf_ptr = g_nvram_buf;
    size_t cur_pos = 0;
    
    while (cur_pos < g_nvram_buf_size)
    {
        VSS_VARIABLE_STORE_HEADER *vss_header = (VSS_VARIABLE_STORE_HEADER*)buf_ptr;
        switch (vss_header->Signature)
        {
            case NVRAM_VSS_STORE_SIGNATURE:
            case NVRAM_APPLE_SVS_STORE_SIGNATURE:
            {
                uint8_t *store_ptr = buf_ptr + sizeof(VSS_VARIABLE_STORE_HEADER);
                uint32_t store_size = vss_header->Size - sizeof(VSS_VARIABLE_STORE_HEADER);
                while (store_ptr < buf_ptr + store_size)
                {
                    VSS_VARIABLE_HEADER *var_header = (VSS_VARIABLE_HEADER*)(store_ptr);
                    if (var_header->StartId == NVRAM_VSS_VARIABLE_START_ID)
                    {
                        if (var_header->State == NVRAM_VSS_VARIABLE_HEADER_VALID || var_header->State == NVRAM_VSS_VARIABLE_ADDED)
                        {
                            CHAR16 *name_ptr = (CHAR16*)((char*)var_header + sizeof(VSS_VARIABLE_HEADER));
                            struct nvram_variables *cur_entry = NULL;
                            int found = 0;
                            TAILQ_FOREACH(cur_entry, &g_nvram_vars, entries)
                            {
                                if (memcmp(name_ptr, cur_entry->name, cur_entry->name_size) == 0)
                                {
                                    found = 1;
                                    break;
                                }
                            }
                            if (found == 0)
                            {
                                auto new_entry = static_cast<struct nvram_variables *>(my_malloc(sizeof(struct nvram_variables)));
                                memcpy(&new_entry->guid, &var_header->VendorGuid, sizeof(EFI_GUID));
                                if (var_header->NameSize <= sizeof(new_entry->name))
                                {
                                    memcpy(new_entry->name, name_ptr, var_header->NameSize);
                                }
                                else
                                {
                                    memcpy(new_entry->name, name_ptr, sizeof(new_entry->name));
                                }
                                new_entry->name_size = var_header->NameSize;
                                new_entry->data_size = var_header->DataSize;
                                new_entry->data = static_cast<uint8_t *>(my_malloc(var_header->DataSize));
                                memcpy(new_entry->data, (char*)var_header + sizeof(VSS_VARIABLE_HEADER) + var_header->NameSize, var_header->DataSize);
                                TAILQ_INSERT_TAIL(&g_nvram_vars, new_entry, entries);
                            }
                        }
                        store_ptr += var_header->DataSize + var_header->NameSize + sizeof(VSS_VARIABLE_HEADER);
                    }
                    else
                    {
                        store_ptr += 1;
                    }
                }
                buf_ptr += vss_header->Size;
                cur_pos += vss_header->Size;
                break;
            }
            case NVRAM_NVAR_ENTRY_SIGNATURE:
            {
                auto nvar_header = (NVAR_ENTRY_HEADER*)buf_ptr;
                // GUID can be stored with the variable or in a separate store, so there will only be an index of it
                uint32_t name_offset = (nvar_header->Attributes & NVRAM_NVAR_ENTRY_GUID) ? sizeof(EFI_GUID) : sizeof(UINT8);
                auto name_ptr = (CHAR8*)(nvar_header + 1) + name_offset;
                std::wstring var_name;
                uint32_t name_size = 0;
                if (nvar_header->Attributes & NVRAM_NVAR_ENTRY_DATA_ONLY)
                {
                    DEBUG_MSG("Data only variables not supported at the moment");
                    buf_ptr += nvar_header->Size;
                    cur_pos += nvar_header->Size;
                    break;
                }
                if (nvar_header->Attributes & NVRAM_NVAR_ENTRY_ASCII_NAME) {
                    // Name is stored as ASCII string of CHAR8s
                    var_name = to_wstring(name_ptr);
                    name_size = var_name.length() + 1;
                }
                else
                {
                    // Name is stored as UCS2 string of CHAR16s
                    var_name = reinterpret_cast<wchar_t*>(name_ptr);
                    name_size = (var_name.length() + 1) * sizeof(wchar_t);
                }

                // Get entry GUID
                EFI_GUID guid{};
                if (nvar_header->Attributes & NVRAM_NVAR_ENTRY_GUID)
                {
                    // GUID is stored in the variable itself
                    guid = *reinterpret_cast<EFI_GUID*>(nvar_header + 1);
                }
                else
                {
                    // GUID is stored in GUID list at the end of the store
                    auto guidIndex = *(UINT8*)(nvar_header + 1);

                    // The list begins at the end of the store and goes backwards
                    auto guid_ptr = reinterpret_cast<EFI_GUID*>(g_nvram_buf + g_nvram_buf_size) - 1 - guidIndex;
                    guid = *guid_ptr;
                }

                auto new_entry = static_cast<struct nvram_variables*>(my_malloc(sizeof(struct nvram_variables)));
                memcpy(&new_entry->guid, &guid, sizeof(EFI_GUID));
                if (var_name.length() <= sizeof(new_entry->name))
                {
                    memcpy(new_entry->name, var_name.c_str(), var_name.length() * 2 + sizeof(wchar_t));
                }
                else
                {
                    memcpy(new_entry->name, var_name.c_str(), sizeof(new_entry->name));
                }
                new_entry->name_size = name_size;
                new_entry->data_size = nvar_header->Size - (name_offset + name_size + sizeof(NVAR_ENTRY_HEADER));
                new_entry->data = static_cast<uint8_t*>(my_malloc(new_entry->data_size));
                memcpy(new_entry->data, (unsigned char*)(name_ptr + name_size), new_entry->data_size);
                TAILQ_INSERT_TAIL(&g_nvram_vars, new_entry, entries);

                buf_ptr += nvar_header->Size;
                cur_pos += nvar_header->Size;
                break;
            }
            default:
            {
                buf_ptr += 1;
                cur_pos += 1;
                break;
            }
        }
    }
    return;
}

#pragma endregion
