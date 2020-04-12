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
 * Created by fG! on 02/05/16.
 * Copyright © 2016-2019 Pedro Vilaca. All rights reserved.
 * reverser@put.as - https://reverse.put.as
 *
 * unicorn_hooks.c
 *
 * Unicorn hooks that we use to emulate EFI services
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

#include "unicorn_hooks.h"

#include <stdio.h>
#include <getopt.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <mman/sys/mman.h>
#include <string.h>
#include <unistd.h>
#include <string.h>
#include <sys/queue.h>

#include "pe_definitions.h"
#include "efi_definitions.h"
#include "logging.h"
#include "efi_runtime_hooks.h"
#include "efi_boot_hooks.h"
#include "config.h"
#include "nvram.h"
#include "debugger.h"
#include "cmds.h"
#include "global_cmds.h"
#include "breakpoints.h"
#include "loader.h"
#include "unicorn_macros.h"
#include "mem_utils.h"
#include "capstone_utils.h"
#include "taint.h"
#include <algorithm>

struct unicorn_hooks
{
    TAILQ_ENTRY(unicorn_hooks) entries;
    uc_hook hook;
    uint64_t begin;
    uint64_t end;
    int type;
};

TAILQ_HEAD(unicorn_hooks_tailq, unicorn_hooks);

struct unicorn_hooks_tailq g_hooks = TAILQ_HEAD_INITIALIZER(g_hooks);

#pragma region Helper functions

/*
 * helper function to add a new Unicorn hook and bookkeep hooks in our internal structure
 *
 */
int
add_unicorn_hook(uc_engine *uc, int type, void *callback, uint64_t begin, uint64_t end)
{
    struct unicorn_hooks *new_hook = NULL;
    new_hook = static_cast<struct unicorn_hooks *>(my_malloc(sizeof(struct unicorn_hooks)));
    new_hook->begin = begin;
    new_hook->end = end;
    new_hook->type = type;
    
    if (uc_hook_add(uc, &new_hook->hook, type, callback, NULL, begin, end) != UC_ERR_OK)
    {
        ERROR_MSG("Failed to add Unicorn hook.");
        free(new_hook);
        return 1;
    }
    
    TAILQ_INSERT_TAIL(&g_hooks, new_hook, entries);
    
    return 0;
}

int
del_unicorn_hook(uc_engine *uc, int type, uint64_t begin, uint64_t end)
{
    struct unicorn_hooks *cur_hook = NULL;
    struct unicorn_hooks *tmp_hook = NULL;
    
    TAILQ_FOREACH_SAFE(cur_hook, &g_hooks, entries, tmp_hook)
    {
        if (cur_hook->type == type &&
            cur_hook->begin == begin &&
            cur_hook->end == end)
        {
            if (uc_hook_del(uc, cur_hook->hook) != UC_ERR_OK)
            {
                ERROR_MSG("Error deleting Unicorn hook.");
                return 1;
            }
            free(cur_hook);
            return 0;
        }
    }
    return 0;
}

#pragma endregion

#pragma region Hooks code

/*
 * hook to deal with interrupts
 * not currently used
 */
void
hook_interrupt(uc_engine *uc, uint32_t intno, void *user_data)
{
    DEBUG_MSG("Hit interrupt nr %d", intno);
    uint64_t r_rsp = 0;
    uc_reg_read(uc, UC_X86_REG_RSP, &r_rsp);
    uint64_t backtrace = 0;
    uc_mem_read(uc, r_rsp, &backtrace, sizeof(backtrace));
    DEBUG_MSG("Backtrace 0x%llx", backtrace);
    uint64_t r_rip = backtrace;
    uc_reg_write(uc, UC_X86_REG_RIP, &r_rip);
}

/*
 * main hook we used to trace over code
 *
 * we fake breakpoints here by comparing the current address against installed breakpoints
 * and if it matches we launch the cli prompt
 *
 */
void
hook_code(uc_engine *uc, uint64_t address, uint32_t size, void *user_data)
{
//    DEBUG_MSG("Hit code at 0x%llx", address);
    
    if (g_break)
    {
        /* display current CPU context like gdbinit */
        context_cmd(NULL, uc);
        /* and let the user take control */
        prompt_loop();
        g_break = false;
    }

    bp_flags flags;
    if (find_breakpoint(address, &flags) == 0)
    {
        /* display current CPU context like gdbinit */
        context_cmd(NULL, uc);
        /* and let the user take control */
        prompt_loop();
        /* if it's a temporary breakpoint remove it from the list */
        if (BooleanFlagOn(flags, kTempBreakpoint))
        {
            del_breakpoint(address);
        }
    }

    cs_insn* insn = NULL;
    get_instruction(uc, address, &insn);

    const auto& _1st_opnd = insn->detail->x86.operands[0];
    const auto& _2nd_opnd = insn->detail->x86.operands[1];
    if ((_1st_opnd.type == X86_OP_REG) &&
        (_1st_opnd._access == CS_AC_WRITE) &&
        (_2nd_opnd.type == X86_OP_MEM) &&
        (_2nd_opnd._access == CS_AC_READ))
    {
        /* memory to register */
        uint64_t base = 0;
        retrieve_capstone_register_contents(uc, _2nd_opnd.mem.base, &base);
        auto eff_addr = base + _2nd_opnd.mem.disp;
        if (std::find(tainted_addresses.begin(), tainted_addresses.end(), eff_addr) == tainted_addresses.end())
        {
            /* un-taint register */
            if (removeRegTainted(_1st_opnd.reg))
            {
                OUTPUT_TAINT("Un-taint register at 0x%llx: %s %s", address, insn->mnemonic, insn->op_str);
            }
            return;
        }

        //DEBUG_MSG("Address %ull is tainted", eff_addr);
        //DEBUG_MSG("%s %s", insn->mnemonic, insn->op_str);
        /* taint the register */
        if (taintReg(_1st_opnd.reg))
        {
            OUTPUT_TAINT("Tainting register at 0x%llx: %s %s", address, insn->mnemonic, insn->op_str);
        }
    }
    else if ((_1st_opnd.type == X86_OP_REG) &&
             (_1st_opnd._access == CS_AC_WRITE) &&
             (_2nd_opnd.type == X86_OP_REG) &&
             (_2nd_opnd._access == CS_AC_READ))
    {
        /* register to register */
        if (checkAlreadyRegTainted(_2nd_opnd.reg))
        {
            if (taintReg(_1st_opnd.reg))
            {
                OUTPUT_TAINT("Tainting register at 0x%llx: %s %s", address, insn->mnemonic, insn->op_str);
            }
        }
        else
        {
            if (removeRegTainted(_1st_opnd.reg))
            {
                OUTPUT_TAINT("Removing taint from register at 0x%llx: %s %s", address, insn->mnemonic, insn->op_str);
            }
        }
    }
    else if ((_1st_opnd.type == X86_OP_MEM) &&
             (_1st_opnd._access == CS_AC_WRITE) &&
             (_2nd_opnd.type == X86_OP_REG) &&
             (_2nd_opnd._access == CS_AC_READ))
    {
        /* register to memory */
        uint64_t base = 0;
        retrieve_capstone_register_contents(uc, _1st_opnd.mem.base, &base);
        auto eff_addr = base + _1st_opnd.mem.disp;

        if (checkAlreadyRegTainted(_2nd_opnd.reg))
        {
            /* taint all memory region*/
            OUTPUT_TAINT("Tainting memory at 0x%llx: %s %s", address, insn->mnemonic, insn->op_str);
            tainted_addresses.push_back(eff_addr);
        }
        else
        {
            /* remove taint, in case it was tainted */
            if (removeMemTainted(eff_addr))
            {
                OUTPUT_TAINT("Removing taint from memory at 0x%llx: %s %s", address, insn->mnemonic, insn->op_str);
            }
        }

        
        //DEBUG_MSG("%s %s", insn->mnemonic, insn->op_str);
    }
}

/*
 * some test hook to trace the caller of a function
 */
void
hook_caller(uc_engine *uc, uint64_t address, uint32_t size, void *user_data)
{
    DEBUG_MSG("Hit code at 0x%llx", address);
    
    uint64_t r_rsp = 0;
    uc_reg_read(uc, UC_X86_REG_RSP, &r_rsp);
    uint64_t backtrace = 0;
    uc_mem_read(uc, r_rsp, &backtrace, sizeof(backtrace));
    DEBUG_MSG("Backtrace 0x%llx", backtrace);
}

/*
 * hook to be used when we hit unmapped Unicorn memory
 * this is used to detect addresses we didn't map and are used by the binary being emulated
 */
bool
hook_unmapped_mem(uc_engine *uc, uc_mem_type type, uint64_t address, int size, int64_t value, void *user_data)
{
    uint64_t reg_rip = 0;
    if (uc_reg_read(uc, UC_X86_REG_RIP, &reg_rip) != UC_ERR_OK)
    {
        ERROR_MSG("Failed to read RIP");
    }
    DEBUG_MSG("Memory exception at 0x%llx", reg_rip);
    
    print_x86_registers(uc);
    print_x86_debug_registers(uc);
    
    uint64_t r_rsp = 0;
    uc_reg_read(uc, UC_X86_REG_RSP, &r_rsp);
    uint64_t backtrace = 0;
    uc_mem_read(uc, r_rsp, &backtrace, sizeof(backtrace));
    DEBUG_MSG("Backtrace 0x%llx", backtrace);
    switch(type) {
        case UC_MEM_READ_UNMAPPED:
            ERROR_MSG("Read from invalid memory at 0x%llx, data size = %u", address, size);
            break;
        case UC_MEM_WRITE_UNMAPPED:
            ERROR_MSG("Write to invalid memory at 0x%llx, data size = %u, data value = 0x%llx", address, size, value);
            break;
        case UC_MEM_FETCH_PROT:
            ERROR_MSG("Fetch from non-executable memory at 0x%llx", address);
            break;
        case UC_MEM_WRITE_PROT:
            ERROR_MSG("Write to non-writeable memory at 0x%llx, data size = %u, data value = 0x%llx", address, size, value);
            break;
        case UC_MEM_READ_PROT:
            ERROR_MSG("Read from non-readable memory at 0x%llx, data size = %u", address, size);
            break;
        default:
            ERROR_MSG("UC_HOOK_MEM_INVALID type: %d at 0x%llx", type, address);
            break;
    }
    DEBUG_MSG("Unmapped mem hit 0x%llx", address);
    /* and let the user take control */
    prompt_loop();
    return 0;
}

bool
hook_valid_mem(uc_engine* uc, uc_mem_type type, uint64_t address, int size, int64_t value, void* user_data)
{
    bp_flags flags;
    if (find_breakpoint(address, &flags) == 0)
    {
        if (!BooleanFlagOn(flags, kDataBreakpoint))
        {
            /* not a data breakpoint */
            return 0;
        }

        /* display current CPU context like gdbinit */
        context_cmd(NULL, uc);
        /* and let the user take control */
        prompt_loop();
        /* if it's a temporary breakpoint remove it from the list */
        if (BooleanFlagOn(flags, kTempBreakpoint))
        {
            del_breakpoint(address);
        }
    }

    return 0;
}

bool
hook_invalid_insn(uc_engine* uc, void* user_data)
{
    ERROR_MSG("Encountered an invalid instruction");
    DEBUG_MSG("Dumping CPU context");

    /* display current CPU context like gdbinit */
    context_cmd(NULL, uc);
    /* and let the user take control */
    prompt_loop();
    
    return false;
}

#pragma endregion
