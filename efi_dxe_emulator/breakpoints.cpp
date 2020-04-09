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
 * Created by fG! on 29/04/16.
 * Copyright © 2016-2019 Pedro Vilaca. All rights reserved.
 * reverser@put.as - https://reverse.put.as
 *
 * breakpoints.c
 *
 * EFI debugger breakpoint related functions and commands
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

#include "breakpoints.h"

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <string.h>
#include <sys/queue.h>
#include <errno.h>
#include <unicorn/unicorn.h>

#include "pe_definitions.h"
#include "efi_definitions.h"
#include "logging.h"
#include "efi_runtime_hooks.h"
#include "efi_boot_hooks.h"
#include "config.h"
#include "nvram.h"
#include "debugger.h"
#include "cmds.h"
#include "unicorn_hooks.h"
#include "capstone_utils.h"
#include "mem_utils.h"
#include "string_ops.h"
#include <stdexcept>

struct breakpoints_tailq g_breakpoints = TAILQ_HEAD_INITIALIZER(g_breakpoints);

static int add_bpt_cmd(const char *exp, uc_engine *uc);
static int del_bpt_cmd(const char *exp, uc_engine *uc);
static int list_bpt_cmd(const char *exp, uc_engine *uc);
static int stepo_cmd(const char *exp, uc_engine *uc);
static int stepi_cmd(const char *exp, uc_engine *uc);
static int add_tmp_bpt_cmd(const char *exp, uc_engine *uc);
static int cfz_cmd(const char *exp, uc_engine *uc);

#pragma region Exported functions

void
register_breakpoint_cmds(uc_engine *uc)
{
    add_user_cmd("b", NULL, add_bpt_cmd, "Install breakpoint.\n\nb ADDRESS", uc);
    add_user_cmd("bpd", NULL, del_bpt_cmd, "Remove breakpoint.\n\nbpd ADDRESS", uc);
    add_user_cmd("bpl", NULL, list_bpt_cmd, "List all installed breakpoints.\n\nbpl", uc);
    add_user_cmd("stepo", "so", stepo_cmd, "Step over code.\n\nstepo", uc);
    add_user_cmd("tb", NULL, add_tmp_bpt_cmd, "Install temporary breakpoint.\n\ntb ADDRESS", uc);
    add_user_cmd("stepi", "si", stepi_cmd, "Step into code.\n\nstepi", uc);
    add_user_cmd("cfz", NULL, cfz_cmd, "Switch zero flag (not working).\n\ncfz", uc);
}

int
add_breakpoint(uint64_t target_addr, uint64_t target_len, enum bp_type type)
{
    struct breakpoint *tmp_entry = NULL;
    
    TAILQ_FOREACH(tmp_entry, &g_breakpoints, entries)
    {
        if (target_addr >= tmp_entry->address && target_addr <= (tmp_entry->address + tmp_entry->length))
        {
            ERROR_MSG("Breakpoint already exists.");
            return -1;
        }
    }
    
    auto new_entry = static_cast<struct breakpoint *>(my_malloc(sizeof(struct breakpoint)));
    new_entry->address = target_addr;
    new_entry->length = target_len;
    new_entry->type = type;
    /* we can't add to Unicorn hooks because it doesn't work so we just add to the breakpoint list */
    //        if (add_unicorn_hook(UC_HOOK_CODE, NULL, target_addr, target_addr + target_len) != 0)
    //        {
    //            ERROR_MSG("Failed to add Unicorn breakpoint hook for 0x%llx.", target_addr);
    //            return 1;
    //        }
    /* everything went ok, add to the list */
    TAILQ_INSERT_TAIL(&g_breakpoints, new_entry, entries);
    return 0;
}

int
del_breakpoint(uint64_t target_addr)
{
    int err = -1;
    struct breakpoint *cur_entry = NULL;
    struct breakpoint *tmp_entry = NULL;
    TAILQ_FOREACH_SAFE(cur_entry, &g_breakpoints, entries, tmp_entry)
    {
        if (target_addr >= cur_entry->address && target_addr <= (cur_entry->address + cur_entry->length))
        {
            TAILQ_REMOVE(&g_breakpoints, cur_entry, entries);
            //            if (uc_hook_del(uc, cur_entry->hook) != UC_ERR_OK)
            //            {
            //                ERROR_MSG("Failed to delete Unicorn breakpoint hook for 0x%llx.", target_addr);
            //            }
            free(cur_entry);
            err = 0;
            break;
        }
    }
    return err;
}

int
find_breakpoint(uint64_t addr, int *type)
{
    struct breakpoint *tmp_entry = NULL;
    TAILQ_FOREACH(tmp_entry, &g_breakpoints, entries)
    {
        if (addr >= tmp_entry->address && addr <= (tmp_entry->address + tmp_entry->length))
        {
            *type = tmp_entry->type;
            return 0;
        }
    }
    
    *type = -1;
    return -1;
}

#pragma endregion

#pragma region Commands functions

static int
add_bpt_cmd(const char *exp, uc_engine *uc)
{
    auto tokens = tokenize(exp);
    _ASSERT(tokens.at(0) == "b");

    errno = 0;
    
    std::string token;
    uint64_t bpt_addr = 0;
    
    /* we need a target address */
    try
    {
        token = tokens.at(1);
    }
    catch (const std::out_of_range&)
    {
        ERROR_MSG("Missing argument(s).");
        return 0;
    }

    /* must be in 0x format */
    if (token.starts_with("0x"))
    {
        bpt_addr = strtoull(token.c_str(), NULL, 16);
        DEBUG_MSG("Breakpoint target address is 0x%llx", bpt_addr);
    }
    /* check if name of boot/runtime service */
    else
    {
        bpt_addr = lookup_runtime_services_table(token);
        bpt_addr = bpt_addr ? bpt_addr : lookup_boot_services_table(token);
        if (bpt_addr == 0)
        {
            ERROR_MSG("Invalid argument(s).");
            return 0;
        }
    }
    
    uint64_t bpt_len = 0;
    /* try to get a length, optional argument */
    try
    {
        token = tokens.at(2);
    }
    catch (const std::out_of_range&)
    {
        token = "";
    }

    if (!token.empty())
    {
        if (token.starts_with("0x"))
        {
            bpt_len = strtoull(token.c_str(), NULL, 16);
            DEBUG_MSG("Breakpoint length is 0x%llx.", bpt_len);
        }
        else
        {
            bpt_len = strtoull(token.c_str(), NULL, 10);
            if (errno == EINVAL || errno == ERANGE)
            {
                ERROR_MSG("Invalid argument(s).");
                return 0;
            }
            DEBUG_MSG("Breakpoint length is 0x%llx.", bpt_len);
        }
    }
    
    add_breakpoint(bpt_addr, bpt_len, kPermBreakpoint);
    return 0;
}

static int
del_bpt_cmd(const char *exp, uc_engine *uc)
{
    auto tokens = tokenize(exp);
    _ASSERT(tokens.at(0) == "bpd");

    std::string token;
    try
    {
        token = tokens.at(1);
    }
    catch (const std::out_of_range&)
    {
        /* we need a target address */
        ERROR_MSG("Missing argument(s).");
        return 0;
    }

    /* must be in 0x format */
    if (token.starts_with("0x"))
    {
        auto bpt_addr = strtoull(token.c_str(), nullptr, 16);
        if (del_breakpoint(bpt_addr) != 0)
        {
            ERROR_MSG("Breakpoint not found.");
        }
        return 0;
    }
    /* decimal number implies breakpoint index */
    else
    {
        auto bpt_nr = std::strtoull(token.c_str(), NULL, 10);
        if (errno == EINVAL || errno == ERANGE)
        {
            ERROR_MSG("Invalid argument(s).");
            return 0;
        }
        int count = 1;
        struct breakpoint *tmp_entry = NULL;
        TAILQ_FOREACH(tmp_entry, &g_breakpoints, entries)
        {
            if (count == bpt_nr)
            {
                if (del_breakpoint(tmp_entry->address) != 0)
                {
                    ERROR_MSG("Breakpoint not found.");
                }
                return 0;
            }
            count++;
        }
        ERROR_MSG("Breakpoint not found.");
        return 0;
    }

    return 0;
}

static int
list_bpt_cmd(const char *exp, uc_engine *uc)
{
    struct breakpoint *tmp_entry = NULL;
    int count = 0;
    
    TAILQ_FOREACH(tmp_entry, &g_breakpoints, entries)
    {
        count++;
    }
    
    if (count == 0)
    {
        OUTPUT_MSG("No breakpoints.");
        return 0;
    }
    
    int i = 1;
    OUTPUT_MSG("Num    Address                  Length");
    TAILQ_FOREACH(tmp_entry, &g_breakpoints, entries)
    {
        OUTPUT_MSG("%3d    0x%016llx       %lld", i, tmp_entry->address, tmp_entry->length);
        i++;
    }

    return 0;
}

static int
add_tmp_bpt_cmd(const char *exp, uc_engine *uc)
{
    errno = 0;
    
    char *token = NULL;
    uint64_t bpt_addr = 0;
    
    char *local_exp = NULL;
    char *local_exp_ptr = NULL;
    local_exp_ptr = local_exp = strdup(exp);
    if (local_exp == NULL)
    {
        ERROR_MSG("strdup failed");
        return 0;
    }

    strsep(&local_exp, " ");
    token = strsep(&local_exp, " ");
    
    /* we need a target address */
    if (token == NULL)
    {
        ERROR_MSG("Missing argument(s).");
        free(local_exp_ptr);
        return 0;
    }
    /* must be in 0x format */
    if (strncmp(token, "0x", 2) == 0)
    {
        bpt_addr = strtoull(token, NULL, 16);
        DEBUG_MSG("Temporary breakpoint target address is 0x%llx", bpt_addr);
    }
    /* everything else is invalid */
    else
    {
        ERROR_MSG("Invalid argument(s).");
        free(local_exp_ptr);
        return 0;
    }
    
    uint64_t bpt_len = 0;
    /* try to get a length, optional argument */
    token = strsep(&local_exp, " ");
    if (token != NULL)
    {
        if (strncmp(token, "0x", 2) == 0)
        {
            bpt_len = strtoull(token, NULL, 16);
            DEBUG_MSG("Breakpoint length is 0x%llx.", bpt_len);
        }
        else
        {
            bpt_len = strtoull(token, NULL, 10);
            if (errno == EINVAL || errno == ERANGE)
            {
                ERROR_MSG("Invalid argument(s).");
                free(local_exp_ptr);
                return 0;
            }
            DEBUG_MSG("Breakpoint length is 0x%llx.", bpt_len);
        }
    }
    
    free(local_exp_ptr);
    add_breakpoint(bpt_addr, bpt_len, kTempBreakpoint);
    return 0;
}

/*
 * step over code, not going into calls
 * we insert a temporary breakpoint on next instruction
 * and then the hook will take care of removing it
 */
static int
stepo_cmd(const char *exp, uc_engine *uc)
{
    uint64_t r_rip = 0;
    if (uc_reg_read(uc, UC_X86_REG_RIP, &r_rip) != UC_ERR_OK)
    {
        ERROR_MSG("Can't read RIP.");
        return 0;
    }
    
    uint64_t next_addr = 0;
    if (find_next_instruction(uc, r_rip, &next_addr, 1) != 0)
    {
        ERROR_MSG("Failed to find control flow target.");
        return 0;
    }
    
    add_breakpoint(next_addr, 0, kTempBreakpoint);
    return 1;
}

/*
 * step into code, going into calls
 * we insert a temporary breakpoint into the call target
 * and then the hook will take care of removing it
 */
static int
stepi_cmd(const char *exp, uc_engine *uc)
{
    uint64_t r_rip = 0;
    if (uc_reg_read(uc, UC_X86_REG_RIP, &r_rip) != UC_ERR_OK)
    {
        ERROR_MSG("Can't read RIP.");
        return 0;
    }
    
    uint64_t next_addr = 0;
    if (find_next_instruction(uc, r_rip, &next_addr, 0) != 0)
    {
        ERROR_MSG("Failed to find control flow target.");
        return 0;
    }
    
    add_breakpoint(next_addr, 0, kTempBreakpoint);
    return 1;
}

/*
 * XXX: not working, Unicorn doesn't update internal rflags? due to JIT?
 */
static int
cfz_cmd(const char *exp, uc_engine *uc)
{
    uint64_t r_rflags = 0;
    if (uc_reg_read(uc, UC_X86_REG_EFLAGS, &r_rflags) != UC_ERR_OK)
    {
        ERROR_MSG("Can't read RFLAGS.");
        return 0;
    }
    
    if ((r_rflags >> 6) & 1)
    {
        r_rflags = r_rflags & ~0x40;
    }
    else
    {
        r_rflags = r_rflags | 0x40;
    }
    if (uc_reg_write(uc, UC_X86_REG_EFLAGS, &r_rflags) != UC_ERR_OK)
    {
        ERROR_MSG("Failed to write RFLAGS.");
        return 0;
    }
    return 0;
}

#pragma endregion
