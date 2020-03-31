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
 * config.h
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

#include <sys/queue.h>

/* default will be located at $HOME path */
#define HISTORY_FILE    ".efi_emulator_history"
/* relative to CWD */
#define GUIDS_FILE      "guids.csv"

#define HOOK_SIZE                            1
/* change to match the base address of your DXE driver */
#define EXEC_ADDRESS                0x00000000
#define EXEC_SIZE             64 * 1024 * 1024
#define STACK_ADDRESS               0x20000000
#define STACK_SIZE             8 * 1024 * 1024
#define EFI_SYSTEM_TABLE_ADDRESS    0x30000000
#define EFI_SYSTEM_TABLE_SIZE  2 * 1024 * 1024
#define EFI_HEAP_ADDRESS            0x40000000
#define EFI_HEAP_SIZE         64 * 1024 * 1024
#define EFI_TRAMPOLINE_ADDRESS      0x50000000
#define EFI_TRAMPOLINE_SIZE        1024 * 1024  /* 1MB is way more than necessary */

#define DISPLAY_DEBUG_REGISTERS 1

/* 0 - disable, 1 - dump to console, 2 - dump to file */
#define CONFIG_SHOW_BACKTRACE   1

struct config_protocols
{
    TAILQ_ENTRY(config_protocols) entries;
    char *path;
};

TAILQ_HEAD(config_protocols_tailq, config_protocols);

struct configuration
{
    char *target_file;
    char *nvram_file;
    char *guids_file;
    char *history_file;
    char *serial_number;
    char *hex_editor;
    struct config_protocols_tailq protos;
};

extern struct configuration g_config;
