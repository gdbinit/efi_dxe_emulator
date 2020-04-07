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
 * Created by fG! on 27/04/16.
 * Copyright © 2016-2019 Pedro Vilaca. All rights reserved.
 * reverser@put.as - https://reverse.put.as
 *
 * debugger.c
 *
 * EFI debugger related functions
 * Mostly memory and register related
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

#include "debugger.h"

#include <stdio.h>
#include <getopt.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <mman/sys/mman.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <ctype.h>
#include <string>

#include "pe_definitions.h"
#include "efi_definitions.h"
#include "logging.h"
#include "efi_runtime_hooks.h"
#include "efi_boot_hooks.h"
#include "config.h"
#include "nvram.h"
#include "cmds.h"
#include "breakpoints.h"
#include "unicorn_macros.h"
#include "capstone_utils.h"
#include "unicorn_utils.h"
#include "mem_utils.h"
#include "string_ops.h"
#include "sync.h"
#include <stdexcept>
#include "events.h"

extern EFI_SYSTEM_TABLE g_efi_table;

int examine_mem_cmd(const char *exp, uc_engine *uc);
int examine_register_cmd(const char *exp, uc_engine *uc);
int set_mem_cmd(const char *exp, uc_engine *uc);
int print_guid_cmd(const char *exp, uc_engine *uc);
int set_register_cmd(const char *exp, uc_engine *uc);
int signal_event_cmd(const char* exp, uc_engine* uc);

bool g_break = false;
BOOL WINAPI HandlerRoutine(_In_ DWORD dwCtrlType);

#pragma region Functions to register the commands

int
register_debugger_cmds(uc_engine *uc)
{
    add_user_cmd("context", NULL, context_cmd, "Display current CPU context.\n\ncontext", uc);
    add_user_cmd("x", NULL, examine_mem_cmd, "Examine memory.\n\nx/SIZE ADDRESS", uc);
    add_user_cmd("xr", NULL, examine_register_cmd, "Examine memory pointed by register.\n\nxr/SIZE register", uc);
    add_user_cmd("s", NULL, set_mem_cmd, "Set memory.\n\ns/SIZE ADDRESS BYTES\nSIZE must be 1,2,4,8 bytes", uc);
    add_user_cmd("sr", NULL, set_register_cmd, "Set register.\n\nsr REGISTER VALUE\nREGISTER is a valid general register\nVALUE the new register value", uc);
    add_user_cmd("guid", NULL, print_guid_cmd, "Print GUID.\n\nguid ADDRESS", uc);
    add_user_cmd("disassemble", NULL, disassemble_cmd, "Displays disassembled code.\n\ndisassemble [ADDRESS]", uc);
    add_user_cmd("signal", NULL, signal_event_cmd, "Signals an EFI_EVENT.\n\nsignal [EFI_EVENT]", uc);

    // Not a debugger command per se, but nevertheless we register it here.
    BOOL err = SetConsoleCtrlHandler(HandlerRoutine, TRUE);
    return (err != FALSE) ? (0) : (-1);
}

#pragma endregion

#pragma region Commands functions

int
examine_mem_cmd(const char *exp, uc_engine *uc)
{
    errno = 0;
    
    size_t exp_len = strlen(exp) + 1;
    if (exp_len <= 1)
    {
        ERROR_MSG("Bad expression.");
        return 0;
    }
    if (exp[1] != '/')
    {
        ERROR_MSG("Bad format.");
        return 0;
    }
    char *local_exp = NULL;
    char *local_exp_ptr = NULL;
    local_exp_ptr = local_exp = strdup(exp);
    if (local_exp == NULL)
    {
        ERROR_MSG("strdup failed");
        return 0;
    }
    
    char *expression = NULL;
    char *address = NULL;
    /* get rid of command string */
    strsep(&local_exp, "/");
    /* extract expression - size in our case */
    expression = strsep(&local_exp, " ");
    /* extract target address */
    address = strsep(&local_exp, " ");
    
    if (expression == NULL || address == NULL)
    {
        ERROR_MSG("Missing arguments.");
        free(local_exp_ptr);
        return 0;
    }
    
    uint64_t total_bytes = strtoull(expression, NULL, 0);
    if (errno == EINVAL || errno == ERANGE)
    {
        ERROR_MSG("Invalid argument(s).");
        free(local_exp_ptr);
        return 0;
    }

    uint64_t source_addr = strtoull(address, NULL, 0);
    if (errno == EINVAL || errno == ERANGE)
    {
        ERROR_MSG("Invalid argument(s).");
        free(local_exp_ptr);
        return 0;
    }

    free(local_exp_ptr);

    auto buffer = static_cast<unsigned char *>(my_malloc(total_bytes));
    uc_mem_read(uc, source_addr, buffer, total_bytes);

    /* output data in hex and characters if possible */
    uint64_t i = 0;
    uint64_t x = 0;
    uint64_t z = 0;
    uint64_t linelength = 0;
    while (i < total_bytes)
    {
        fprintf(stdout, "0x%llx: ", source_addr);
        linelength = (total_bytes - i) <= 16 ? total_bytes - i : 16;
        z = i;
        for (x = 0; x < linelength; x++)
        {
            fprintf(stdout, "%02X ", buffer[z++]);
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
            fprintf(stdout, "%c", isascii(buffer[z]) && isprint(buffer[z]) ? buffer[z] : '.');
            z++;
        }
        i += 16;
        fprintf(stdout, "|\n");
        source_addr += linelength;
    }
    
    free(buffer);
    return 0;
}

int
examine_register_cmd(const char *exp, uc_engine *uc)
{
    uc_err err = UC_ERR_OK;
    
    errno = 0;
    
    size_t exp_len = strlen(exp) + 1;
    if (exp_len <= 1)
    {
        ERROR_MSG("Bad expression.");
        return 0;
    }
    if (exp[2] != '/')
    {
        ERROR_MSG("Bad format.");
        return 0;
    }
    char *local_exp = NULL;
    char *local_exp_ptr = NULL;
    local_exp_ptr = local_exp = strdup(exp);
    if (local_exp == NULL)
    {
        ERROR_MSG("strdup failed");
        return 0;
    }
    
    char *expression = NULL;
    char *arg_register = NULL;
    strsep(&local_exp, "/");
    expression = strsep(&local_exp, " ");
    arg_register = strsep(&local_exp, " ");
    free(local_exp_ptr);
    
    if (expression == NULL || arg_register == NULL)
    {
        ERROR_MSG("Missing arguments.");
        return 0;
    }
    
    uint64_t total_bytes = strtoull(expression, NULL, 0);
    if (errno == EINVAL || errno == ERANGE)
    {
        ERROR_MSG("Invalid argument(s).");
        return 0;
    }
    
    int target_register = UC_X86_REG_INVALID;
    
    if (arg_register[0] == 'R' ||
        arg_register[0] == 'r' ||
        arg_register[0] == 'E' ||
        arg_register[0] == 'e')
    {
        ;
    }
    else
    {
        DEBUG_MSG("Invalid register argument.");
        return 0;
    }
    
    /* convert this to Unicorn register */
    target_register = convert_register_to_unicorn(arg_register);
    if (target_register == UC_X86_REG_INVALID)
    {
        ERROR_MSG("Invalid target register.");
        return 0;
    }
    
    uint64_t target_memory_addr = 0;
    err = uc_reg_read(uc, target_register, &target_memory_addr);
    VERIFY_UC_OPERATION_RET(err, 0, "Failed to read register");
    
    auto buffer = static_cast<unsigned char *>(my_malloc(total_bytes));
    err = uc_mem_read(uc, target_memory_addr, buffer, total_bytes);
    VERIFY_UC_OPERATION_RET(err, 0, "Failed to read memory at address 0x%llx", target_memory_addr);
    
    /* output data in hex and characters if possible */
    uint64_t i = 0;
    uint64_t x = 0;
    uint64_t z = 0;
    uint64_t linelength = 0;
    while (i < total_bytes)
    {
        fprintf(stdout, "0x%llx: ", target_memory_addr);
        linelength = (total_bytes - i) <= 16 ? total_bytes - i : 16;
        z = i;
        for (x = 0; x < linelength; x++)
        {
            fprintf(stdout, "%02X ", buffer[z++]);
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
            fprintf(stdout, "%c", isascii(buffer[z]) && isprint(buffer[z]) ? buffer[z] : '.');
            z++;
        }
        i += 16;
        fprintf(stdout, "|\n");
        target_memory_addr += linelength;
    }
    
    free(buffer);
    return 0;
}

int
set_mem_cmd(const char *exp, uc_engine *uc)
{
    errno = 0;
    
    size_t exp_len = strlen(exp) + 1;
    if (exp_len <= 1)
    {
        ERROR_MSG("Bad expression.");
        return 0;
    }
    
    if (exp[1] != '/')
    {
        ERROR_MSG("Bad format.");
        return 0;
    }
    
    char *local_exp = NULL;
    char *local_exp_ptr = NULL;
    local_exp_ptr = local_exp = strdup(exp);
    if (local_exp == NULL)
    {
        ERROR_MSG("strdup failed");
        return 0;
    }
    
    char *address = NULL;
    char *expression = NULL;
    size_t address_len = 0;
    char *bytes_to_write = NULL;
    strsep(&local_exp, "/");
    expression = strsep(&local_exp, " ");
    address = strsep(&local_exp, " ");
    bytes_to_write = strsep(&local_exp, " ");
    free(local_exp_ptr);
    
    if (address == NULL || bytes_to_write == NULL)
    {
        ERROR_MSG("Missing arguments.");
        return 0;
    }
    
//    DEBUG_MSG("1: %s 2: %s 3: %s 4: %s", token, expression, address, bytes_to_write);

    address_len = strlen(address);
    
    if (address_len < 2)
    {
        ERROR_MSG("Invalid register argument(s).");
        return 0;
    }

    if (address[0] == '0' && address[1] == 'x')
    {
        ;
    }
    else
    {
        DEBUG_MSG("Invalid target argument.");
        return 0;
    }
    
    uint64_t target_addr = 0;
    
    target_addr = strtoull(address, NULL, 0x10);
    
    uint64_t write_size = strtoull(expression, NULL, 10);
    if (errno == EINVAL || errno == ERANGE)
    {
        ERROR_MSG("Invalid write size argument(s) %d", errno);
        return 0;
    }
    
    switch (write_size) {
        case 1:
        case 2:
        case 4:
        case 8:
            break;
        default:
        {
            ERROR_MSG("Size must be 1, 2, 4, 8 only.");
            return 0;
        }
    }

    uint64_t bytes = strtoull(bytes_to_write, NULL, 0);
    if (errno == EINVAL || errno == ERANGE)
    {
        ERROR_MSG("Invalid bytes to write.");
        return 0;
    }
    
    if (uc_mem_write(uc, target_addr, &bytes, write_size) != UC_ERR_OK)
    {
        ERROR_MSG("Failed to write to memory address 0x%llx.", target_addr);
        return 0;
    }
    return 0;
}

int
set_register_cmd(const char *exp, uc_engine *uc)
{
    errno = 0;
    
    size_t exp_len = strlen(exp) + 1;
    if (exp_len <= 1)
    {
        ERROR_MSG("Bad expression.");
        return 0;
    }
    
    char *local_exp = NULL;
    char *local_exp_ptr = NULL;
    local_exp_ptr = local_exp = strdup(exp);
    if (local_exp == NULL)
    {
        ERROR_MSG("strdup failed");
        return 0;
    }

    char *arg_register = NULL;
    char *arg_value = NULL;
    strsep(&local_exp, " ");
    arg_register = strsep(&local_exp, " ");
    arg_value = strsep(&local_exp, " ");
    free(local_exp_ptr);
    
    if (arg_register == NULL || arg_value == NULL)
    {
        ERROR_MSG("Missing arguments.");
        return 0;
    }
    
    int target_register = UC_X86_REG_INVALID;
    
    if (arg_register[0] == 'R' ||
        arg_register[0] == 'r' ||
        arg_register[0] == 'E' ||
        arg_register[0] == 'e')
    {
        ;
    }
    else
    {
        DEBUG_MSG("Invalid register argument.");
        return 0;
    }
    
    /* convert this to Unicorn register */
    target_register = convert_register_to_unicorn(arg_register);
    if (target_register == UC_X86_REG_INVALID)
    {
        ERROR_MSG("Invalid target register.");
        return 0;
    }
    
    uint64_t target_value = strtoull(arg_value, NULL, 0);
    if (errno == EINVAL || errno == ERANGE)
    {
        ERROR_MSG("Invalid value to write.");
        return 0;
    }
    
    if (uc_reg_write(uc, target_register, &target_value) != UC_ERR_OK)
    {
        ERROR_MSG("Failed to update register.");
        return 0;
    }
    
    return 0;
}

int
print_guid_cmd(const char *exp, uc_engine *uc)
{
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
    free(local_exp_ptr);
    
    /* we need a target address */
    if (token == NULL)
    {
        ERROR_MSG("Missing argument(s).");
        return 0;
    }
    /* must be in 0x format */
    if (strncmp(token, "0x", 2) == 0)
    {
        bpt_addr = strtoull(token, NULL, 16);
    }
    /* everything else is invalid */
    else
    {
        ERROR_MSG("Invalid argument(s).");
        return 0;
    }
    
    EFI_GUID guid = {0};
    uc_mem_read(uc, bpt_addr, &guid, sizeof(EFI_GUID));
    
    EFI_GUID *guid_ptr = &guid;
    OUTPUT_MSG("GUID: %08X-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X",
               guid_ptr->Data1, guid_ptr->Data2, guid_ptr->Data3,
               guid_ptr->Data4[0], guid_ptr->Data4[1], guid_ptr->Data4[2], guid_ptr->Data4[3],
               guid_ptr->Data4[4], guid_ptr->Data4[5], guid_ptr->Data4[6], guid_ptr->Data4[7]);

    return 0;
}

int
context_cmd(const char *exp, uc_engine *uc)
{
    // Sync with IDA
    UpdateState(uc);

    print_x86_registers(uc);
#if defined(DISPLAY_DEBUG_REGISTERS) && DISPLAY_DEBUG_REGISTERS == 1
    print_x86_debug_registers(uc);
#endif
    uint64_t r_rip = 0;
    if (uc_reg_read(uc, UC_X86_REG_RIP, &r_rip) != UC_ERR_OK)
    {
        ERROR_MSG("Can't read RIP.");
        return 0;
    }
    print_dissassembly(uc, r_rip);
    return 0;
}

int
disassemble_cmd(const char* exp, uc_engine* uc)
{
    uint64_t r_rip;

    std::string disassemble_exp(exp);
    size_t pos = disassemble_exp.find("0x");
    if (pos == std::string::npos)
    {
        if (uc_reg_read(uc, UC_X86_REG_RIP, &r_rip) != UC_ERR_OK)
        {
            ERROR_MSG("Can't read RIP.");
            return 0;
        }
    }
    else
    {
        r_rip = std::strtoull(disassemble_exp.c_str() + pos, nullptr, 0);
    }

    print_dissassembly(uc, r_rip);
    return 0;
}

int
signal_event_cmd(const char* exp, uc_engine* uc)
{
    auto tokens = tokenize(exp);
    _ASSERT(tokens.at(0) == "signal");

    uint64_t event_id;
    try
    {
        event_id = strtoull(tokens.at(1).c_str(), nullptr, 0);
    }
    catch (const std::out_of_range&)
    {
        ERROR_MSG("Missing or invalid event id");
        return 0;
    }

    signal_efi_event(uc, (EFI_EVENT)event_id);
    dispatch_event_notification_routines(uc);
    return 0;
}

BOOL WINAPI HandlerRoutine(_In_ DWORD dwCtrlType)
{
    BOOL rc;

    switch (dwCtrlType)
    {
    case CTRL_C_EVENT:
        DEBUG_MSG("Got CTRL-C event\n");
        // Signal the debugger to break at the next instruction
        g_break = true;
        rc = TRUE;
        break;
    default:
        rc = FALSE;
        break;
    }

    return rc;
}

#pragma endregion

#pragma region Other functions

void
print_x86_registers(uc_engine *uc)
{
    struct x86_thread_state64 thread_state = {0};

    if (get_x64_registers(uc, &thread_state) != 0)
    {
        ERROR_MSG("Can't retrieve x86_64 registers.");
        return;
    }
    
    OUTPUT_MSG(SEPARATOR_COLOR "-----------------------------------------------------------------------------------------------------------------------[regs]" ANSI_COLOR_RESET);
    fprintf(stdout, REGISTER_COLOR "  RAX:" ANSI_COLOR_RESET " 0x%016llx  " REGISTER_COLOR "RBX:" ANSI_COLOR_RESET " 0x%016llx  " REGISTER_COLOR "RBP:" ANSI_COLOR_RESET " 0x%016llx  " REGISTER_COLOR "RSP:" ANSI_COLOR_RESET " 0x%016llx  " EFLAGS_COLOR, thread_state.__rax, thread_state.__rbx, thread_state.__rbp, thread_state.__rsp);
    (thread_state.__rflags >> 0xB) & 1 ? printf("O ") : printf("o ");
    (thread_state.__rflags >> 0xA) & 1 ? printf("D ") : printf("d ");
    (thread_state.__rflags >> 0x9) & 1 ? printf("I ") : printf("i ");
    (thread_state.__rflags >> 0x8) & 1 ? printf("T ") : printf("t ");
    (thread_state.__rflags >> 0x7) & 1 ? printf("S ") : printf("s ");
    (thread_state.__rflags >> 0x6) & 1 ? printf("Z ") : printf("z ");
    (thread_state.__rflags >> 0x4) & 1 ? printf("A ") : printf("a ");
    (thread_state.__rflags >> 0x2) & 1 ? printf("P ") : printf("p ");
    (thread_state.__rflags) & 1 ? printf("C ") : printf("c ");
    fprintf(stdout, "\n" ANSI_COLOR_RESET);
    OUTPUT_MSG(REGISTER_COLOR "  RDI:" ANSI_COLOR_RESET " 0x%016llx  " REGISTER_COLOR "RSI:" ANSI_COLOR_RESET " 0x%016llx  " REGISTER_COLOR "RDX:" ANSI_COLOR_RESET " 0x%016llx  " REGISTER_COLOR "RCX:" ANSI_COLOR_RESET " 0x%016llx  " REGISTER_COLOR "RIP:" ANSI_COLOR_RESET " 0x%016llx", thread_state.__rdi, thread_state.__rsi, thread_state.__rdx, thread_state.__rcx, thread_state.__rip);
    OUTPUT_MSG(REGISTER_COLOR "  R8 :" ANSI_COLOR_RESET " 0x%016llx  " REGISTER_COLOR "R9 :" ANSI_COLOR_RESET " 0x%016llx  " REGISTER_COLOR "R10:" ANSI_COLOR_RESET " 0x%016llx  " REGISTER_COLOR "R11:" ANSI_COLOR_RESET " 0x%016llx  " REGISTER_COLOR "R12:" ANSI_COLOR_RESET " 0x%016llx", thread_state.__r8, thread_state.__r9, thread_state.__r10, thread_state.__r11, thread_state.__r12);
    OUTPUT_MSG(REGISTER_COLOR "  R13:" ANSI_COLOR_RESET " 0x%016llx  " REGISTER_COLOR "R14:" ANSI_COLOR_RESET " 0x%016llx  " REGISTER_COLOR "R15:" ANSI_COLOR_RESET " 0x%016llx  " REGISTER_COLOR "EFLAGS:" ANSI_COLOR_RESET " 0x%016llx", thread_state.__r13, thread_state.__r14, thread_state.__r15, thread_state.__rflags);
}

void
print_x86_debug_registers(uc_engine *uc)
{
    struct x86_debug_state64 state = {0};
    
    if (get_x64_debug_registers(uc, &state) != 0)
    {
        ERROR_MSG("Can't retrieve x86_64 debug registers.");
        return;
    }
    
    fprintf(stdout, SEPARATOR_COLOR "------------------------------------------------------------------------------------------------------------[debug registers]\n" ANSI_COLOR_RESET);
    fprintf(stdout, REGISTER_COLOR "  DR0:" ANSI_COLOR_RESET " 0x%016llx" REGISTER_COLOR "  DR1:" ANSI_COLOR_RESET " 0x%016llx" REGISTER_COLOR "  DR2:" ANSI_COLOR_RESET " 0x%016llx" REGISTER_COLOR "  DR3:" ANSI_COLOR_RESET " 0x%016llx\n", state.__dr0, state.__dr1, state.__dr2, state.__dr3);
    fprintf(stdout, REGISTER_COLOR "  DR4:" ANSI_COLOR_RESET " 0x%016llx" REGISTER_COLOR "  DR5:" ANSI_COLOR_RESET " 0x%016llx" REGISTER_COLOR "  DR6:" ANSI_COLOR_RESET " 0x%016llx" REGISTER_COLOR "  DR7:" ANSI_COLOR_RESET " 0x%016llx\n", state.__dr4, state.__dr5, state.__dr6, state.__dr7);
}

#pragma endregion
