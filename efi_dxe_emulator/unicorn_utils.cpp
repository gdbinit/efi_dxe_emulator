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
 * Created by fG! on 05/06/16.
 * Copyright © 2016-2019 Pedro Vilaca. All rights reserved.
 * reverser@put.as - https://reverse.put.as
 *
 * unicorn_utils.c
 *
 * Functions to do some useful Unicorn related operations
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

#include "unicorn_utils.h"

#include <string.h>

#include "logging.h"
#include "config.h"
#include "unicorn_macros.h"
#include "mem_utils.h"

/*
 * helper function at allocates all Unicorn emulation memory areas we will need
 */
int
allocate_emulation_mem(uc_engine *uc)
{
    uc_err err = UC_ERR_OK;
    
    /* executables area */
    err = uc_mem_map(uc, EXEC_ADDRESS, EXEC_SIZE, UC_PROT_ALL);
    VERIFY_UC_OPERATION_RET(err, 1, "Failed to allocate Unicorn executables memory area");
    
    /* stack area */
    err = uc_mem_map(uc, STACK_ADDRESS, STACK_SIZE, UC_PROT_ALL);
    VERIFY_UC_OPERATION_RET(err, 1, "Failed to allocate Unicorn stack memory area");
    
    /* heap area */
    err = uc_mem_map(uc, EFI_HEAP_ADDRESS, EFI_HEAP_SIZE, UC_PROT_ALL);
    VERIFY_UC_OPERATION_RET(err, 1, "Failed to allocate Unicorn heap memory area");
    
    /* allocate memory to hold EFI_SYSTEM_TABLE and other required tables */
    err = uc_mem_map(uc, EFI_SYSTEM_TABLE_ADDRESS, EFI_SYSTEM_TABLE_SIZE, UC_PROT_READ | UC_PROT_WRITE);
    VERIFY_UC_OPERATION_RET(err, 1, "Failed to allocate Unicorn EFI system tables memory area");
    
    /* allocate memory to hold various trampolines */
    err = uc_mem_map(uc, EFI_TRAMPOLINE_ADDRESS, EFI_TRAMPOLINE_SIZE, UC_PROT_ALL);
    VERIFY_UC_OPERATION_RET(err, 1, "Failed to allocate Unicorn trampoline memory area");
    
    return 0;
}

/*
 * initialize registers to a clean state
 * Stack not cleaned up
 * to be used after we load secondary images
 */
int
initialize_unicorn_registers(uc_engine *uc)
{
    uc_err err = UC_ERR_OK;
    
    int x86_64_regs[] = {
        UC_X86_REG_RIP,
        UC_X86_REG_RAX, UC_X86_REG_RBX, UC_X86_REG_RBP,
        UC_X86_REG_RDI, UC_X86_REG_RSI, UC_X86_REG_RDX, UC_X86_REG_RCX,
        UC_X86_REG_R8, UC_X86_REG_R9, UC_X86_REG_R10,
        UC_X86_REG_R11, UC_X86_REG_R12, UC_X86_REG_R13, UC_X86_REG_R14,
        UC_X86_REG_R15, UC_X86_REG_CS, UC_X86_REG_FS, UC_X86_REG_GS, UC_X86_REG_EFLAGS
    };
    uint64_t vals[sizeof(x86_64_regs)] = {0};
    void *ptrs[sizeof(x86_64_regs)] = {0};
    
    for (int i = 0; i < sizeof(x86_64_regs); i++)
    {
        ptrs[i] = &vals[i];
    }
    
    /* count argument is the number of elements in the array! */
    err = uc_reg_write_batch(uc, x86_64_regs, ptrs, sizeof(x86_64_regs)/sizeof(*x86_64_regs));
    VERIFY_UC_OPERATION_RET(err, 1, "Failed to initialize registers");

    return 0;
}

/*
 * write Mac machine serial number into Unicorn memory (fixed physical memory address on real machines)
 */
int
write_serial_number(uc_engine *uc, char *serial_number)
{
    DEBUG_MSG("Writing machine serial number to Unicorn memory...");
    
    uc_err err = UC_ERR_OK;
    
    /* allocate physical memory area */
    /* used for machine serial number for now */
    /* XXX: move back to allocate_emulation_mem() if this area needed by something else */
    err = uc_mem_map(uc, 0xffff0000, 1024 * 1024, UC_PROT_ALL);
    VERIFY_UC_OPERATION_RET(err, 1, "Failed to allocate Unicorn physical memory area");
    
    size_t serial_length = strlen(serial_number);
    /* we need to add two digits, 0x20 and 0xFF (serial always ends in 0xFF (end marker?)) */
    serial_length += 3;
    
    auto serial_to_write = static_cast<char *>(my_calloc(1, serial_length));
    snprintf(serial_to_write, serial_length, "%s\x20\xFF", serial_number);
    
    err = uc_mem_write(uc, 0xffffff08, serial_to_write, serial_length-1);
    VERIFY_UC_OPERATION_RET(err, 1, "Failed to write serial number to physical memory area.");
    free(serial_to_write);
    
    return 0;
}

/*
 * type = 0 : log to console
 * type = 1 : log to file
 */
void
log_unicorn_backtrace(uc_engine *uc, char *function_name, int type)
{
    uc_err err = UC_ERR_OK;
    
    uint64_t r_rsp = 0;
    err = uc_reg_read(uc, UC_X86_REG_RSP, &r_rsp);
    VERIFY_UC_OPERATION_VOID(err, "Failed to read RSP");
    uint64_t backtrace = 0;
    err = uc_mem_read(uc, r_rsp, &backtrace, sizeof(backtrace));
    VERIFY_UC_OPERATION_VOID(err, "Failed to read backtrace memory");
    
    DEBUG_MSG("Hit %s from 0x%llx", function_name, backtrace);
}

int
convert_register_to_unicorn(const char *src_reg)
{
    if (strcasecmp(src_reg, "RAX") == 0)
    {
        return UC_X86_REG_RAX;
    }
    else if (strcasecmp(src_reg, "RBX") == 0)
    {
        return UC_X86_REG_RBX;
    }
    else if (strcasecmp(src_reg, "RBP") == 0)
    {
        return UC_X86_REG_RBP;
    }
    else if (strcasecmp(src_reg, "RSP") == 0)
    {
        return UC_X86_REG_RSP;
    }
    else if (strcasecmp(src_reg, "RDI") == 0)
    {
        return UC_X86_REG_RDI;
    }
    else if (strcasecmp(src_reg, "RSI") == 0)
    {
        return UC_X86_REG_RSI;
    }
    else if (strcasecmp(src_reg, "RDX") == 0)
    {
        return UC_X86_REG_RDX;
    }
    else if (strcasecmp(src_reg, "RCX") == 0)
    {
        return UC_X86_REG_RCX;
    }
    else if (strcasecmp(src_reg, "RIP") == 0)
    {
        return UC_X86_REG_RIP;
    }
    else if (strcasecmp(src_reg, "R8") == 0)
    {
        return UC_X86_REG_R8;
    }
    else if (strcasecmp(src_reg, "R9") == 0)
    {
        return UC_X86_REG_R9;
    }
    else if (strcasecmp(src_reg, "R10") == 0)
    {
        return UC_X86_REG_R10;
    }
    else if (strcasecmp(src_reg, "R11") == 0)
    {
        return UC_X86_REG_R11;
    }
    else if (strcasecmp(src_reg, "R12") == 0)
    {
        return UC_X86_REG_R12;
    }
    else if (strcasecmp(src_reg, "R13") == 0)
    {
        return UC_X86_REG_R13;
    }
    else if (strcasecmp(src_reg, "R14") == 0)
    {
        return UC_X86_REG_R14;
    }
    else if (strcasecmp(src_reg, "R15") == 0)
    {
        return UC_X86_REG_R15;
    }
    else if (strcasecmp(src_reg, "RFLAGS") == 0)
    {
        return UC_X86_REG_EFLAGS;
    }
    else
    {
        return UC_X86_REG_INVALID;
    }
}

int
get_x64_registers(uc_engine *uc, struct x86_thread_state64 *state)
{
    if (uc == NULL || state == NULL)
    {
        ERROR_MSG("Invalid arguments.");
        return 1;
    }
    
    int x86_64_regs[] = {
        UC_X86_REG_RIP,
        UC_X86_REG_RAX, UC_X86_REG_RBX, UC_X86_REG_RBP, UC_X86_REG_RSP,
        UC_X86_REG_RDI, UC_X86_REG_RSI, UC_X86_REG_RDX, UC_X86_REG_RCX,
        UC_X86_REG_R8, UC_X86_REG_R9, UC_X86_REG_R10,
        UC_X86_REG_R11, UC_X86_REG_R12, UC_X86_REG_R13, UC_X86_REG_R14,
        UC_X86_REG_R15, UC_X86_REG_CS, UC_X86_REG_FS, UC_X86_REG_GS, UC_X86_REG_EFLAGS
    };
    uint64_t vals[sizeof(x86_64_regs)] = {0};
    void *ptrs[sizeof(x86_64_regs)] = {0};
    
    for (int i = 0; i < sizeof(x86_64_regs); i++)
    {
        ptrs[i] = &vals[i];
    }
    
    if (uc_reg_read_batch(uc, x86_64_regs, ptrs, sizeof(x86_64_regs)/sizeof(*x86_64_regs)) != UC_ERR_OK)
    {
        ERROR_MSG("Failed to read registers.");
        return 1;
    }
    
    state->__rip = vals[0];
    state->__rax = vals[1];
    state->__rbx = vals[2];
    state->__rbp = vals[3];
    state->__rsp = vals[4];
    state->__rdi = vals[5];
    state->__rsi = vals[6];
    state->__rdx = vals[7];
    state->__rcx = vals[8];
    state->__r8  = vals[9];
    state->__r9  = vals[10];
    state->__r10 = vals[11];
    state->__r11 = vals[12];
    state->__r12 = vals[13];
    state->__r13 = vals[14];
    state->__r14 = vals[15];
    state->__r15 = vals[16];
    state->__cs  = vals[17];
    state->__fs  = vals[18];
    state->__cs  = vals[19];
    state->__rflags = vals[20];
    
    return 0;
}

int
get_x64_exception_registers(uc_engine *uc, struct x86_exception_state64 *state)
{
    return 0;
}

int
get_x64_debug_registers(uc_engine *uc, struct x86_debug_state64 *state)
{
    if (uc == NULL || state == NULL)
    {
        ERROR_MSG("Invalid arguments.");
        return 1;
    }
    
    int regs[] = {
        UC_X86_REG_DR0, UC_X86_REG_DR1, UC_X86_REG_DR2, UC_X86_REG_DR3,
        UC_X86_REG_DR4, UC_X86_REG_DR5, UC_X86_REG_DR6, UC_X86_REG_DR7
    };
    
    uint64_t vals[sizeof(regs)] = { 0 };
    void *ptrs[sizeof(regs)] = {0};
    
    for (int i = 0; i < sizeof(regs); i++)
    {
        ptrs[i] = &vals[i];
    }
    
    if (uc_reg_read_batch(uc, regs, ptrs, sizeof(regs)) != UC_ERR_OK)
    {
        ERROR_MSG("Failed to read debug registers.");
        return 1;
    }
    
    state->__dr0 = vals[0];
    state->__dr1 = vals[1];
    state->__dr2 = vals[2];
    state->__dr3 = vals[3];
    state->__dr4 = vals[4];
    state->__dr5 = vals[5];
    state->__dr6 = vals[6];
    state->__dr7 = vals[7];
    
    return 0;
}

int
get_eflags(uc_engine *uc, struct eflags *out_eflags)
{
    uint64_t r_eflags = 0;
    if (uc_reg_read(uc, UC_X86_REG_EFLAGS, &r_eflags) != UC_ERR_OK)
    {
        ERROR_MSG("Can't read EFLAGS.");
        return 1;
    }
    
    out_eflags->carry = r_eflags & 1 ?  1 : 0;
    out_eflags->parity = (r_eflags >> 2) & 1 ? 1 : 0;
    out_eflags->adjust = (r_eflags >> 4) & 1 ? 1 : 0;
    out_eflags->zero = (r_eflags >> 6) & 1 ? 1 : 0;
    out_eflags->sign = (r_eflags >> 7) & 1 ? 1 : 0;
    out_eflags->trap = (r_eflags >> 8) & 1 ? 1 : 0;
    out_eflags->interrupt = (r_eflags >> 9) & 1 ? 1 : 0;
    out_eflags->direction = (r_eflags >> 10) & 1 ? 1 : 0;
    out_eflags->overflow = (r_eflags >> 11) & 1 ? 1 : 0;
    out_eflags->resume = (r_eflags >> 16) & 1 ? 1 : 0;
    out_eflags->virtual_mode = (r_eflags >> 17) & 1 ? 1 : 0;
    out_eflags->alignemnt = (r_eflags >> 18) & 1 ? 1 : 0;
    out_eflags->virtual_interrupt = (r_eflags >> 19) & 1 ? 1 : 0;
    out_eflags->virtual_pending = (r_eflags >> 20) & 1 ? 1 : 0;
    out_eflags->cpuid = (r_eflags >> 21) & 1 ? 1 : 0;
    
    return 0;
}
