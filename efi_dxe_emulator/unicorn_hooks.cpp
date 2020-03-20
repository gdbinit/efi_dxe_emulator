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

/* Apple's public key used to sign the SCBO files
 * since we are not emulating the filesystem we are going to inject it directly into emulation memory
 * at a certain breakpoint
 */
unsigned char apple_public_key[] = "\x13\x78\x07\x72\x47\x12\x81\x22\x39\x4B\x43\x1C\x65\x48\x19\xF1\xBA\xF5\x3F\xD6\x30\xDA\x25\x69\x3F\x7D\x4C\x24\xA5\xAE\x70\x57\x1D\x60\x45\x7D\x01\x4B\x75\x61\x0C\xF1\x9C\x6D\xC5\xD7\x12\x66\xB9\x9F\xC3\x27\x7B\xDD\x91\xE7\x38\x71\xBF\x36\x63\xE5\x2B\x26\x4C\xB0\x5C\xFC\x3C\x7B\xCC\x84\x70\xFB\x60\xE1\xB3\xAB\x3A\x37\x4F\x27\xCE\x5F\x38\x07\xD9\x85\xD6\xC0\x2E\x28\xF6\x27\x60\x8D\xD2\x64\x01\x05\xD8\x62\x3A\xD6\xEA\xD9\x40\x71\x87\xDD\x9C\xCB\x5B\xCC\x5C\x51\x0C\xE1\x72\xB6\xF7\x77\xF9\x20\xE2\xFB\x6B\xDA\xF1\x79\x51\x18\x9E\x50\x3F\xBB\x0E\xB3\x5A\x00\xF6\xED\x1C\xDE\xA8\x0E\x49\x37\x81\x67\x45\xE9\x72\xF4\x37\xC9\x3F\xFB\x28\xF0\x89\x56\x39\x1F\x28\xC4\x11\xB5\x55\x06\x3B\xFD\xC8\x45\x96\xAE\x68\x20\x7F\x3E\x84\x11\xFC\x8E\xE6\x68\x14\xC0\x07\x8A\x74\x1B\xB9\x5A\x24\x6A\x9A\x09\x2A\x53\x38\x40\x8E\xCE\x1F\xB4\x62\x09\x5D\x47\x0C\x92\x1D\x88\x78\xBC\xDA\x0D\xAE\x82\x19\x61\xBF\x1F\xD3\xDF\xA1\xCA\x2E\xAA\xE8\x22\xFB\x51\x13\xE7\x88\x53\x71\xE4\xDF\x10\x8C\xA5\x7F\x3E\x90\x28\xEA\x34\x3E\x44\x6D\xAA\x05\xA9";

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
    
    /* XXX: a hack to inject directly the Apple public key into the right location
     * avoiding to emulate the whole protocol that locates the keys in the EFI filesystem
     */
    if (address == 0x10002272)
    {
        DEBUG_MSG("Hit Apple public key injection breakpoint!");
        // retrieve the address of the buffer
        uint64_t r_rdx = 0;
        uc_err err = UC_ERR_OK;
        err = uc_reg_read(uc, UC_X86_REG_RDX, &r_rdx);
        VERIFY_UC_OPERATION_VOID(err, "Failed to read RDX");
        DEBUG_MSG("Public key buffer is at address 0x%llx", r_rdx);
        // write the public key to the buffer
        err = uc_mem_write(uc, r_rdx, apple_public_key, sizeof(apple_public_key));
        VERIFY_UC_OPERATION_VOID(err, "Failed to write Apple public key to Unicorn memory");
        // set a success return value for protocol call
        uint64_t r_rax = 0;
        err = uc_reg_write(uc, UC_X86_REG_RAX, &r_rax);
        VERIFY_UC_OPERATION_VOID(err, "Failed to write RAX register");
        // skip the call to next instruction
        uint64_t r_rip = 0x10002277;
        err = uc_reg_write(uc, UC_X86_REG_RIP, &r_rip);
        VERIFY_UC_OPERATION_VOID(err, "Failed to write RIP register");
        return;
    }
    
    int type = 0;
    if (find_breakpoint(address, &type) == 0)
    {
        /* display current CPU context like gdbinit */
        context_cmd(NULL, uc);
        /* and let the user take control */
        prompt_loop();
        /* if it's a temporary breakpoint remove it from the list */
        if (type == kTempBreakpoint)
        {
            del_breakpoint(address);
        }
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
        default:
            ERROR_MSG("UC_HOOK_MEM_INVALID type: %d at 0x%llx", type, address);
            return false;
        case UC_MEM_READ_UNMAPPED:
            ERROR_MSG("Read from invalid memory at 0x%llx, data size = %u", address, size);
            return false;
        case UC_MEM_WRITE_UNMAPPED:
            ERROR_MSG("Write to invalid memory at 0x%llx, data size = %u, data value = 0x%llx", address, size, value);
            return false;
        case UC_MEM_FETCH_PROT:
            ERROR_MSG("Fetch from non-executable memory at 0x%llx", address);
            return false;
        case UC_MEM_WRITE_PROT:
            ERROR_MSG("Write to non-writeable memory at 0x%llx, data size = %u, data value = 0x%llx", address, size, value);
            return false;
        case UC_MEM_READ_PROT:
            ERROR_MSG("Read from non-readable memory at 0x%llx, data size = %u", address, size);
            return false;
    }
    DEBUG_MSG("Unmapped mem hit 0x%llx", address);
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
