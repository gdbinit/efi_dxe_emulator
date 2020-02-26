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
 * Created by fG! on 28/10/2019.
 * Copyright © 2016-2019 Pedro Vilaca. All rights reserved.
 * reverser@put.as - https://reverse.put.as
 *
 * capstone_utils.c
 *
 * Functions to do Capstone related operations
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

#include "capstone_utils.h"

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <string.h>
#include <sys/queue.h>
#include <errno.h>

#include <unicorn/unicorn.h>

#include "logging.h"
#include "config.h"
#include "debugger.h"
#include "efi_definitions.h"
#include "efi_boot_hooks.h"
#include "efi_runtime_hooks.h"
#include "unicorn_utils.h"

extern EFI_SYSTEM_TABLE g_efi_table;

static int find_jmp_target(uc_engine *uc, cs_insn *insn, uint64_t *out_addr);
static int find_jxx_target(uc_engine *uc, cs_insn *insn, uint64_t *out_addr);
static int find_call_target(uc_engine *uc, cs_insn *insn, uint64_t *out_addr);

#pragma region Exported functions

/*
 * function to find what is the next instruction to be executed
 * for regular instructions it just returns the next instruction
 * for instructions that change the code flow it will compute the next address
 * for calls it also depends if we want to step into the call or skip over it
 * return 0 for success, -1 otherwrise
 */
int
find_next_instruction(uc_engine *uc, uint64_t src_addr, uint64_t *dst_addr, int step_over)
{
    csh handle = 0;
    cs_insn *insn = NULL;
    size_t count = 0;
    cs_err cserr = 0;
    cs_mode mode = CS_MODE_64;
    cs_arch arch = CS_ARCH_X86;
    if ((cserr = cs_open(arch, mode, &handle)) != CS_ERR_OK)
    {
        ERROR_MSG("Error opening Capstone: %s (%d).", cs_strerror(cserr), cserr);
        return -1;
    }
    /* enable detail - we need fields available in detail field */
    cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);
    /* disassemble! */
    unsigned char buffer[16] = {0};
    if (uc_mem_read(uc, src_addr, buffer, sizeof(buffer)) != UC_ERR_OK)
    {
        ERROR_MSG("Failed to retrieve data to disassemble.");
        return -1;
    }
    count = cs_disasm(handle, buffer, sizeof(buffer), src_addr, 1, &insn);
    if (count < 1)
    {
        ERROR_MSG("Failed to retrieve instruction.");
        return -1;
    }
    
    /* insn must be free'd from here onwards */
    
    /* now we need to compute the target */
    switch (insn[0].id)
    {
        case X86_INS_CALL:
        {
            /* if we want to skip over the call we just return the location of the next instruction */
            if (step_over == 1)
            {
                *dst_addr = src_addr + insn[0].size;
                cs_free(insn, count);
                return 0;
            }
            /* we get the out address from this call */
            if (find_call_target(uc, &insn[0], dst_addr) != 0)
            {
                ERROR_MSG("Failed to find call target address.");
                cs_free(insn, count);
                return -1;
            }
            break;
        }
        case X86_INS_RET:
        {
            uint64_t r_rsp = 0;
            if (uc_reg_read(uc, UC_X86_REG_RSP, &r_rsp) != UC_ERR_OK)
            {
                ERROR_MSG("Can't read RSP.");
                cs_free(insn, count);
                return -1;
            }
            uint64_t ret_addr = 0;
            if (uc_mem_read(uc, r_rsp, &ret_addr, sizeof(ret_addr)) != UC_ERR_OK)
            {
                ERROR_MSG("Can't read memory.");
                cs_free(insn, count);
                return -1;
            }
            *dst_addr = ret_addr;
            break;
        }
        case X86_INS_JMP:
        {
            find_jmp_target(uc, &insn[0], dst_addr);
            break;
        }
            /* conditional jumps */
            /* Capstone does have instruction groups but bundles all jmps in same group */
        case X86_INS_JA:
        case X86_INS_JAE:
        case X86_INS_JB:
        case X86_INS_JBE:
        case X86_INS_JCXZ:
        case X86_INS_JE:
        case X86_INS_JECXZ:
        case X86_INS_JG:
        case X86_INS_JGE:
        case X86_INS_JL:
        case X86_INS_JLE:
        case X86_INS_JNE:
        case X86_INS_JNO:
        case X86_INS_JNP:
        case X86_INS_JNS:
        case X86_INS_JO:
        case X86_INS_JP:
        case X86_INS_JRCXZ:
        case X86_INS_JS:
        {
            find_jxx_target(uc, &insn[0], dst_addr);
            break;
        }
        /* for regular instructions we just return next address */
        default:
        {
            *dst_addr = src_addr + insn[0].size;
            break;
        }
    }
    
out:
    cs_free(insn, count);
    return 0;
}

int reg_map[X86_REG_ENDING] = {0};

static void
initialize_register_map(void)
{
    // 32 bit
    reg_map[X86_REG_EIP] = UC_X86_REG_EIP;
    reg_map[X86_REG_EBP] = UC_X86_REG_EBP;
    reg_map[X86_REG_ESP] = UC_X86_REG_ESP;
    reg_map[X86_REG_EAX] = UC_X86_REG_EAX;
    reg_map[X86_REG_EBX] = UC_X86_REG_EBX;
    reg_map[X86_REG_EDI] = UC_X86_REG_EDI;
    reg_map[X86_REG_ESI] = UC_X86_REG_ESI;
    reg_map[X86_REG_EDX] = UC_X86_REG_EDX;
    reg_map[X86_REG_ECX] = UC_X86_REG_ECX;
    // 64 bit
    reg_map[X86_REG_RIP] = UC_X86_REG_RIP;
    reg_map[X86_REG_RBP] = UC_X86_REG_RBP;
    reg_map[X86_REG_RSP] = UC_X86_REG_RSP;
    reg_map[X86_REG_RAX] = UC_X86_REG_RAX;
    reg_map[X86_REG_RBX] = UC_X86_REG_RBX;
    reg_map[X86_REG_RDI] = UC_X86_REG_RDI;
    reg_map[X86_REG_RSI] = UC_X86_REG_RSI;
    reg_map[X86_REG_RDX] = UC_X86_REG_RDX;
    reg_map[X86_REG_RCX] = UC_X86_REG_RCX;
    reg_map[X86_REG_R8]  = UC_X86_REG_R8;
    reg_map[X86_REG_R9]  = UC_X86_REG_R9;
    reg_map[X86_REG_R10] = UC_X86_REG_R10;
    reg_map[X86_REG_R11] = UC_X86_REG_R11;
    reg_map[X86_REG_R12] = UC_X86_REG_R12;
    reg_map[X86_REG_R13] = UC_X86_REG_R13;
    reg_map[X86_REG_R14] = UC_X86_REG_R14;
    reg_map[X86_REG_R15] = UC_X86_REG_R15;
//    reg_map[X86_REG_] = UC_X86_REG_;
}

int
retrieve_capstone_register_contents(uc_engine *uc, x86_reg reg, uint64_t *out_value)
{
    uint64_t reg_value = 0;
    static int map_init = 0;
    if (map_init == 0)
    {
        initialize_register_map();
        map_init = 1;
    }
    
    if (uc_reg_read(uc, reg_map[reg], &reg_value) != UC_ERR_OK)
    {
        ERROR_MSG("Failed to read register %d", reg);
        return -1;
    }

    *out_value = reg_value;
    return 0;
}


char *
retrieve_efi_call(uc_engine *uc, int64_t offset, unsigned int reg)
{
    uint64_t table_ptr = 0;
    static int map_init = 0;
    if (map_init == 0)
    {
        initialize_register_map();
        map_init = 1;
    }

    if (uc_reg_read(uc, reg_map[reg], &table_ptr) != UC_ERR_OK)
    {
        ERROR_MSG("Failed to read register %d", reg);
        return NULL;
    }
    
    static char full_name[256] = {0};
    if (table_ptr == (uint64_t)g_efi_table.BootServices)
    {
        char *name = lookup_boot_services_table((int)offset);
        if (name != NULL)
        {
            snprintf(full_name, sizeof(full_name), "BootServices->%s()", name);
            full_name[sizeof(full_name)-1] = '\0';
            return full_name;
        }
        return NULL;
    }
    else if (table_ptr == (uint64_t)g_efi_table.RuntimeServices)
    {
        char *name = lookup_runtime_services_table((int)offset);
        if (name != NULL)
        {
            snprintf(full_name, sizeof(full_name), "RunTimeServices->%s()", name);
            full_name[sizeof(full_name)-1] = '\0';
            return full_name;
        }
        return NULL;
    }
    return NULL;
}

void
print_dissassembly(uc_engine *uc, uint64_t addr)
{
    uint64_t r_rip = 0;
    if (uc_reg_read(uc, UC_X86_REG_RIP, &r_rip) != UC_ERR_OK)
    {
        ERROR_MSG("Can't read RIP.");
        return;
    }
    
    csh handle = 0;
    cs_insn *insn = NULL;
    size_t count = 0;
    cs_err cserr = 0;
    cs_mode mode = CS_MODE_64;
    cs_arch arch = CS_ARCH_X86;
    if ( (cserr = cs_open(arch, mode, &handle)) != CS_ERR_OK )
    {
        ERROR_MSG("Error opening Capstone: %s (%d).", cs_strerror(cserr), cserr);
        return;
    }
    /* enable detail - we need fields available in detail field */
    cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);
    /* disassemble! */
    unsigned char buffer[256] = {0};
    if (uc_mem_read(uc, addr, buffer, sizeof(buffer)) != UC_ERR_OK)
    {
        ERROR_MSG("Failed to retrieve data to disassemble.");
        return;
    }
    fprintf(stdout, SEPARATOR_COLOR "-----------------------------------------------------------------------------------------------------------------------[code]\n" ANSI_COLOR_RESET);
    count = cs_disasm(handle, buffer, sizeof(buffer), addr, 10, &insn);
    for (size_t i = 0; i < count; i++)
    {
        fprintf(stdout, "%p: ", (void*)insn[i].address);
        char hex_output[49] = {0};
        memset(hex_output, 0x20, 49);
        size_t length = 9 - insn[i].size;;
        
        if (insn[i].size > 9)
        {
            for (uint16_t x = 0; x < 8; x++)
            {
                fprintf(stdout, "%02x ", insn[i].bytes[x]);
            }
            fprintf(stdout, "%02x", insn[i].bytes[9]);
            fprintf(stdout, "+");
        }
        else
        {
            for (uint16_t x = 0; x < insn[i].size; x++)
            {
                fprintf(stdout, "%02x ", insn[i].bytes[x]);
            }
            
            for (uint16_t x = 0; x < length; x++)
            {
                fprintf(stdout, "   ");
            }
        }
        if (insn[i].id == X86_INS_CALL)
        {
            /*
             * we can only compute this when we are on the instruction
             * since before we are not sure about the base register value
             */
            if (r_rip == insn[i].address && insn[i].detail->x86.operands[0].type == X86_OP_MEM)
            {
                char *service_name = retrieve_efi_call(uc, insn[i].detail->x86.operands[0].mem.disp, insn[i].detail->x86.operands[0].mem.base);
                if (service_name != NULL)
                {
                    fprintf(stdout, "  %s\t%s \x1b[34m -- %s\x1b[0m\n", insn[i].mnemonic, insn[i].op_str, service_name);
                }
                else
                {
                    fprintf(stdout, "  %s\t%s\n", insn[i].mnemonic, insn[i].op_str);
                }
            }
            else
            {
                fprintf(stdout, "  %s\t%s\n", insn[i].mnemonic, insn[i].op_str);
            }
        }
        else if (cs_insn_group(handle, &insn[i], CS_GRP_JUMP) == true)
        {
            if (r_rip == insn[i].address)
            {
                uint64_t target_addr = 0;
                if (find_jxx_target(uc, &insn[i], &target_addr) != 0)
                {
                    ERROR_MSG("Failed to retrieve target jump address.");
                }
                if (target_addr == insn[i].address + insn[i].size)
                {
                    fprintf(stdout, "  %s\t%s \x1b[31m(no jump)\x1b[0m\n", insn[i].mnemonic, insn[i].op_str);
                }
                else
                {
                    fprintf(stdout, "  %s\t%s \x1b[32m(jump)\x1b[0m\n", insn[i].mnemonic, insn[i].op_str);
                }
            }
            else
            {
                fprintf(stdout, "  %s\t%s\n", insn[i].mnemonic, insn[i].op_str);
            }
        }
        else
        {
            if ((insn[i].detail->x86.operands[0].type == X86_OP_MEM &&
                 insn[i].detail->x86.operands[0].mem.base == X86_REG_RIP) ||
                (insn[i].detail->x86.operands[1].type == X86_OP_MEM &&
                 insn[i].detail->x86.operands[1].mem.base == X86_REG_RIP))
            {
                fprintf(stdout, "  %s\t%s  # 0x%llx\n", insn[i].mnemonic, insn[i].op_str, X86_REL_ADDR(insn[i]));
            }
            else if (insn[i].detail->x86.operands[0].type == X86_OP_MEM || insn[i].detail->x86.operands[1].type == X86_OP_MEM)
            {
                if (r_rip == insn[i].address)
                {
                    uint64_t reg_value = 0;
                    if (insn[i].detail->x86.operands[0].type == X86_OP_MEM)
                    {
                        retrieve_capstone_register_contents(uc, insn[i].detail->x86.operands[0].mem.base, &reg_value);
                    }
                    else
                    {
                        retrieve_capstone_register_contents(uc, insn[i].detail->x86.operands[1].mem.base, &reg_value);
                    }
                    fprintf(stdout, "  %s\t%s # 0x%llx\n", insn[i].mnemonic, insn[i].op_str, reg_value + insn[i].detail->x86.disp);
                }
                else
                {
                    fprintf(stdout, "  %s\t%s\n", insn[i].mnemonic, insn[i].op_str);
                }
            }
            else
            {
                fprintf(stdout, "  %s\t%s\n", insn[i].mnemonic, insn[i].op_str);
            }
        }
    }
    cs_free(insn, count);
    fprintf(stdout, SEPARATOR_COLOR "-----------------------------------------------------------------------------------------------------------------------------\n" ANSI_COLOR_RESET);
}

#pragma endregion

#pragma region Local functions

static int
find_jxx_target(uc_engine *uc, cs_insn *insn, uint64_t *dst_addr)
{
    if (insn->id == X86_INS_JMP)
    {
        return 0;
    }
    
    struct eflags flags = {0};
    if (get_eflags(uc, &flags) != 0)
    {
        ERROR_MSG("Failed to retrieve EFLAGS.");
        return -1;
    }
    
    if (insn->detail->x86.operands[0].type != X86_OP_IMM)
    {
        ERROR_MSG("Invalid JXX type");
        return -1;
    }
    /* JE if ZF = 1 */
    if (insn->id == X86_INS_JE)
    {
        /* where the jump is pointing to */
        if (flags.zero == 1)
        {
            *dst_addr = insn->detail->x86.operands[0].imm;
        }
        /* next instruction */
        else
        {
            *dst_addr = insn->address + insn->size;
        }
    }
    /* JNE if ZF = 0 */
    else if (insn->id == X86_INS_JNE)
    {
        *dst_addr = (flags.zero == 0) ? insn->detail->x86.operands[0].imm : insn->address + insn->size;
    }
    /* JA is CF = 0 && ZF = 0 */
    else if (insn->id == X86_INS_JA)
    {
        *dst_addr = (flags.carry == 0 && flags.zero == 0) ? insn->detail->x86.operands[0].imm : insn->address + insn->size;
    }
    /* JAE is CF = 0 */
    else if (insn->id == X86_INS_JAE)
    {
        *dst_addr = (flags.carry == 0) ? insn->detail->x86.operands[0].imm : insn->address + insn->size;
    }
    /* JB if CF = 1 */
    else if (insn->id == X86_INS_JB)
    {
        *dst_addr = (flags.carry == 1) ? insn->detail->x86.operands[0].imm : insn->address + insn->size;
    }
    /* JBE if CF = 1 || ZF = 1 */
    else if (insn->id == X86_INS_JBE)
    {
        *dst_addr = (flags.carry == 1 || flags.zero == 1) ? insn->detail->x86.operands[0].imm : insn->address + insn->size;
    }
    /* JCXZ if CX reg = 0 */
    else if (insn->id == X86_INS_JCXZ)
    {
        uint32_t r_ecx = 0;
        if (uc_reg_read(uc, X86_REG_ECX, &r_ecx) != UC_ERR_OK)
        {
            ERROR_MSG("Failed to read ECX register.");
            return -1;
        }
        *dst_addr = ((r_ecx & 0xFFFF) == 0) ? insn->detail->x86.operands[0].imm : insn->address + insn->size;
    }
    /* JCXZ if ECX reg = 0 */
    else if (insn->id == X86_INS_JECXZ)
    {
        uint32_t r_ecx = 0;
        if (uc_reg_read(uc, X86_REG_ECX, &r_ecx) != UC_ERR_OK)
        {
            ERROR_MSG("Failed to read ECX register.");
            return -1;
        }
        *dst_addr = (r_ecx == 0) ? insn->detail->x86.operands[0].imm : insn->address + insn->size;
    }
    /* JCXZ if RCX reg = 0 */
    else if (insn->id == X86_INS_JRCXZ)
    {
        uint32_t r_rcx = 0;
        if (uc_reg_read(uc, X86_REG_RCX, &r_rcx) != UC_ERR_OK)
        {
            ERROR_MSG("Failed to read RCX register.");
            return -1;
        }
        *dst_addr = (r_rcx == 0) ? insn->detail->x86.operands[0].imm : insn->address + insn->size;
    }
    /* JG if ZF = 0 and SF = OF */
    else if (insn->id == X86_INS_JG)
    {
        *dst_addr = (flags.zero == 0 && flags.sign == flags.overflow) ? insn->detail->x86.operands[0].imm : insn->address + insn->size;
    }
    /* JGE if SF = OF */
    else if (insn->id == X86_INS_JGE)
    {
        *dst_addr = (flags.sign == flags.overflow) ? insn->detail->x86.operands[0].imm : insn->address + insn->size;
    }
    /* JL if SF != OF */
    else if (insn->id == X86_INS_JL)
    {
        *dst_addr = (flags.sign != flags.overflow) ? insn->detail->x86.operands[0].imm : insn->address + insn->size;
    }
    /* JLE if ZF = 1 || SF != OF */
    else if (insn->id == X86_INS_JLE)
    {
        *dst_addr = (flags.zero == 1 || flags.sign != flags.overflow) ? insn->detail->x86.operands[0].imm : insn->address + insn->size;
    }
    /* JNO if OF = 0 */
    else if (insn->id == X86_INS_JNO)
    {
        *dst_addr = (flags.overflow == 0) ? insn->detail->x86.operands[0].imm : insn->address + insn->size;
    }
    /* JNP if PF = 0 */
    else if (insn->id == X86_INS_JNP)
    {
        *dst_addr = (flags.parity == 0) ? insn->detail->x86.operands[0].imm : insn->address + insn->size;
    }
    /* JNS if SF = 0 */
    else if (insn->id == X86_INS_JNS)
    {
        *dst_addr = (flags.sign == 0) ? insn->detail->x86.operands[0].imm : insn->address + insn->size;
    }
    /* JO if OF = 1 */
    else if (insn->id == X86_INS_JO)
    {
        *dst_addr = (flags.overflow == 1) ? insn->detail->x86.operands[0].imm : insn->address + insn->size;
    }
    /* JP if PF = 1 */
    else if (insn->id == X86_INS_JP)
    {
        *dst_addr = (flags.parity == 1) ? insn->detail->x86.operands[0].imm : insn->address + insn->size;
    }
    /* JS if SF = 1 */
    else if (insn->id == X86_INS_JS)
    {
        *dst_addr = (flags.sign == 1) ? insn->detail->x86.operands[0].imm : insn->address + insn->size;
    }
    
    return 0;
}

/*
 * find the target address of a CALL
 * returns 1 on failure
 */
static int
find_call_target(uc_engine *uc, cs_insn *insn, uint64_t *dst_addr)
{
    switch (insn->detail->x86.operands[0].type)
    {
        case X86_OP_REG:
        {
            //            DEBUG_MSG("Call of type OP_REG");
            uint64_t reg_value = 0;
            if (retrieve_capstone_register_contents(uc, insn->detail->x86.operands[0].mem.base, &reg_value) != 0)
            {
                ERROR_MSG("Unable to retrieve register value.");
                return -1;
            }
            *dst_addr = reg_value;
            return 0;
        }
            /* value */
        case X86_OP_IMM:
        {
            //            DEBUG_MSG("Call of type OP_IMM to 0x%llx", insn->detail->x86.operands[0].imm);
            *dst_addr = insn->detail->x86.operands[0].imm;
            return 0;
        }
            /* reg + offset */
        case X86_OP_MEM:
        {
            //            DEBUG_MSG("Call of type OP_MEM");
            uint64_t reg_value = 0;
            if (retrieve_capstone_register_contents(uc, insn->detail->x86.operands[0].mem.base, &reg_value) != 0)
            {
                ERROR_MSG("Unable to retrieve register value.");
                return -1;
            }
            *dst_addr = reg_value + insn->detail->x86.operands[0].mem.disp;
            return 0;
        }
        default:
        {
            ERROR_MSG("Invalid call type");
            return -1;
        }
    }
}

static int
find_jmp_target(uc_engine *uc, cs_insn *insn, uint64_t *dst_addr)
{
    switch (insn->detail->x86.operands[0].type)
    {
        case X86_OP_REG:
        {
            DEBUG_MSG("JMP of type OP_REG");
            uint64_t reg_value = 0;
            if (retrieve_capstone_register_contents(uc, insn->detail->x86.operands[0].mem.base, &reg_value) != 0)
            {
                ERROR_MSG("Unable to retrieve register value.");
                return -1;
            }
            *dst_addr = reg_value;
            return 0;
        }
            /* value */
        case X86_OP_IMM:
        {
            DEBUG_MSG("JMP of type OP_IMM to 0x%llx", insn->detail->x86.operands[0].imm);
            *dst_addr = insn->detail->x86.operands[0].imm;
            return 0;
        }
            /* reg + offset */
        case X86_OP_MEM:
        {
            DEBUG_MSG("JMP of type OP_MEM");
            uint64_t reg_value = 0;
            if (retrieve_capstone_register_contents(uc, insn->detail->x86.operands[0].mem.base, &reg_value) != 0)
            {
                ERROR_MSG("Unable to retrieve register value.");
                return -1;
            }
            *dst_addr = reg_value + insn->detail->x86.operands[0].mem.disp;
            return 0;
        }
        default:
        {
            ERROR_MSG("Invalid JMP type");
            return -1;
        }
    }
    
    return 0;
}

#pragma endregion
