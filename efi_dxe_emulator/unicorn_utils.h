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
 * unicorn_utils.h
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

#pragma once

#include <unicorn/unicorn.h>
#include "config.h"

struct eflags
{
    unsigned int carry : 1;
    unsigned int : 1;
    unsigned int parity : 1;
    unsigned int : 1;
    unsigned int adjust : 1;
    unsigned int : 1;
    unsigned int zero : 1;
    unsigned int sign : 1;
    unsigned int trap : 1;
    unsigned int interrupt : 1;
    unsigned int direction : 1;
    unsigned int overflow : 1;
    unsigned int : 4;
    unsigned int resume : 1;
    unsigned int virtual_mode : 1;
    unsigned int alignemnt : 1;
    unsigned int virtual_interrupt : 1;
    unsigned int virtual_pending : 1;
    unsigned int cpuid : 1;
    unsigned int : 10;
    unsigned int : 32;
};

struct x86_thread_state64
{
    uint64_t    __rax;
    uint64_t    __rbx;
    uint64_t    __rcx;
    uint64_t    __rdx;
    uint64_t    __rdi;
    uint64_t    __rsi;
    uint64_t    __rbp;
    uint64_t    __rsp;
    uint64_t    __r8;
    uint64_t    __r9;
    uint64_t    __r10;
    uint64_t    __r11;
    uint64_t    __r12;
    uint64_t    __r13;
    uint64_t    __r14;
    uint64_t    __r15;
    uint64_t    __rip;
    uint64_t    __rflags;
    uint64_t    __cs;
    uint64_t    __fs;
    uint64_t    __gs;
};

struct x86_exception_state64
{
    uint16_t    __trapno;
    uint16_t    __cpu;
    uint32_t    __err;
    uint64_t    __faultvaddr;
};

struct x86_debug_state64
{
    uint64_t    __dr0;
    uint64_t    __dr1;
    uint64_t    __dr2;
    uint64_t    __dr3;
    uint64_t    __dr4;
    uint64_t    __dr5;
    uint64_t    __dr6;
    uint64_t    __dr7;
};

int initialize_unicorn_registers(uc_engine *uc);
int allocate_emulation_mem(uc_engine *uc);
int write_serial_number(uc_engine *uc, char *serial_number);
int convert_register_to_unicorn(const char *src_reg);
int get_x64_registers(uc_engine *uc, struct x86_thread_state64 *state);
int get_x64_exception_registers(uc_engine *uc, struct x86_exception_state64 *state);
int get_x64_debug_registers(uc_engine *uc, struct x86_debug_state64 *state);
int get_eflags(uc_engine *uc, struct eflags *out_eflags);

void log_unicorn_backtrace(uc_engine *uc, char *function_name, int type);

/* macro allows us to globally remove the backtrace dump we have on the EFI services */
#if defined(CONFIG_SHOW_BACKTRACE) && CONFIG_SHOW_BACKTRACE == 1
#   define LOG_UC_BACKTRACE(uc, msg)  log_unicorn_backtrace(uc, msg, 0);
#elif CONFIG_SHOW_BACKTRACE == 2
#   define LOG_UC_BACKTRACE(uc, msg)  log_unicorn_backtrace(uc, msg, 1);
#else
#   define LOG_UC_BACKTRACE(uc, msg)  do {} while(0)
#endif
