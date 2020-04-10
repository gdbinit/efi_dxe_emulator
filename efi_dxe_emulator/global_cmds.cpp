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
 * Created by fG! on 01/05/16.
 * Copyright © 2016-2019 Pedro Vilaca. All rights reserved.
 * reverser@put.as - https://reverse.put.as
 *
 * global_cmds.c
 *
 * EFI Debugger global commands
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

#include "global_cmds.h"

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <string.h>
#include <sys/queue.h>
#include <assert.h>
#include <unicorn/unicorn.h>
#include <stdexcept>

#include "pe_definitions.h"
#include "efi_definitions.h"
#include "logging.h"
#include "efi_runtime_hooks.h"
#include "efi_boot_hooks.h"
#include "config.h"
#include "nvram.h"
#include "debugger.h"
#include "cmds.h"
#include "loader.h"
#include "string_ops.h"
#include "protocols.h"
#include "guids.h"
#include "events.h"

extern struct bin_images_tailq g_images;
extern struct protocols_list_tailq g_installed_protocols;

static int quit_cmd(const char *exp, uc_engine *uc);
static int run_cmd(const char *exp, uc_engine *uc);
static int continue_cmd(const char *exp, uc_engine *uc);
static int info_cmd(const char *exp, uc_engine *uc);

#pragma region Functions to register the commands

void
register_global_cmds(uc_engine *uc)
{
    add_user_cmd("run", "r", run_cmd, "Start emulating target.\n\nrun", uc);
    add_user_cmd("quit", "q", quit_cmd, "Quit emulator.\n\nquit", uc);
    add_user_cmd("help", "h", help_cmd, "Help.\n\nhelp", uc);
    add_user_cmd("continue", "c", continue_cmd, "Continue running.\n\ncontinue", uc);
    add_user_cmd("info", NULL, info_cmd, "Info.\n\ninfo", uc);
    add_user_cmd("history", NULL, history_cmd, "Display command line history.\n\nhistory", uc);
}

#pragma endregion

#pragma region Commands functions

static int
quit_cmd(const char *exp, uc_engine *uc)
{
    uc_emu_stop(uc);
    exit(0);

    /* unreachable */
    return 1;
}

static int
run_cmd(const char *exp, uc_engine *uc)
{
    return 0;
}

static int
continue_cmd(const char *exp, uc_engine *uc)
{
    return 1;
}

static void
info_cmd_help(void)
{
    OUTPUT_MSG("\"info\" must be followed by the name of an info command.");
    OUTPUT_MSG("List of info subcommands:\n");
    OUTPUT_MSG("info target -- Information about main binary");
    OUTPUT_MSG("info all    -- Information about all mapped binaries");
    OUTPUT_MSG("");
}

static int
info_cmd(const char *exp, uc_engine *uc)
{
    auto tokens = tokenize(exp);
    assert(tokens.at(0) == "info");

    std::string token;
    try
    {
        token = tokens.at(1);
    }
    catch (const std::out_of_range&)
    {
        info_cmd_help();
        return 0;
    }

    struct bin_image *main_image = TAILQ_FIRST(&g_images);
    assert(main_image != NULL);
    
    if (token == "target")
    {
        OUTPUT_MSG("EFI Executable:\n%s", main_image->file_path);
        OUTPUT_MSG("Base address: 0%llx", main_image->base_addr);
        OUTPUT_MSG("Entrypoint: 0x%llx (0x%llx)", main_image->base_addr + main_image->entrypoint, main_image->entrypoint);
        OUTPUT_MSG("Image size: 0x%llx", main_image->buf_size);
        OUTPUT_MSG("Number of sections: %d", main_image->nr_sections);
    }
    else if (token == "all")
    {
        int count = 1;
        struct bin_image *tmp_image = NULL;
        TAILQ_FOREACH(tmp_image, &g_images, entries)
        {
            OUTPUT_MSG("---[ Image #%02d ]---", count++);
            OUTPUT_MSG("EFI Executable: \n%s", tmp_image->file_path);
            OUTPUT_MSG("Mapped address: 0x%llx", tmp_image->mapped_addr);
            OUTPUT_MSG("Mapped entrypoint: 0x%llx", tmp_image->mapped_addr + tmp_image->entrypoint);
            OUTPUT_MSG("Base address: 0%llx", tmp_image->base_addr);
            OUTPUT_MSG("Entrypoint: 0x%llx (0x%llx)", tmp_image->base_addr + tmp_image->entrypoint, tmp_image->entrypoint);
            OUTPUT_MSG("Image size: 0x%llx", tmp_image->buf_size);
            OUTPUT_MSG("Number of sections: %d", tmp_image->nr_sections);
        }
    }
    else if (token == "protocols")
    {
        int count = 1;
        struct protocols_list *tmp_proto = NULL;
        TAILQ_FOREACH(tmp_proto, &g_installed_protocols, entries)
        {
            OUTPUT_MSG("--- [Protocol #%02d ] ---", count++);
            OUTPUT_MSG("GUID: %s", guid_to_string(&tmp_proto->guid));
            OUTPUT_MSG("Friendly name: %s", get_guid_friendly_name(tmp_proto->guid));
            OUTPUT_MSG("Interface: 0x%llx", tmp_proto->iface);
        }
    }
    else if (token == "events")
    {
        for (const auto& ei : g_events)
        {
            OUTPUT_MSG("--- [EFI Event #%02p ] ---", ei.first);
            OUTPUT_MSG("Notification routine: 0x%llx", ei.second.notify_routine);
            OUTPUT_MSG("Notification context: 0x%llx", ei.second.notify_context);
            OUTPUT_MSG("Signaled: %s", ei.second.signaled ? "TRUE" : "FALSE");
        }
    }
    /* everything else is invalid */
    else
    {
        info_cmd_help();
        return 0;
    }
    
    return 0;
}

#pragma endregion
