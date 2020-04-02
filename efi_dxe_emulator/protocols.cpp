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
 * Created by fG! on 06/05/16.
 * Copyright © 2016-2019 Pedro Vilaca. All rights reserved.
 * reverser@put.as - https://reverse.put.as
 *
 * protocols.c
 *
 * Just some test code to emulate a protocol instead of loading the EFI binary that implements it
 * It was a first approach to avoid loading additional binaries before support for it was coded
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

#include "protocols.h"

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/queue.h>

#include "pe_definitions.h"
#include "logging.h"
#include "config.h"
#include "debugger.h"
#include "unicorn_hooks.h"
#include "string_ops.h"
#include "mem_utils.h"
#include "guids.h"

struct protocols_list_tailq g_installed_protocols = TAILQ_HEAD_INITIALIZER(g_installed_protocols);

int
add_protocol(EFI_GUID *guid, uint64_t iface)
{
    struct protocols_list *tmp_entry = 0;
    TAILQ_FOREACH(tmp_entry, &g_installed_protocols, entries)
    {
        if (memcmp(&tmp_entry->guid, guid, sizeof(EFI_GUID)) == 0)
        {
            DEBUG_MSG("Found duplicate entry.");
            return -1;
        }
    }
    
    auto new_entry = static_cast<struct protocols_list *>(my_malloc(sizeof(struct protocols_list)));
    memcpy(&new_entry->guid, guid, sizeof(EFI_GUID));
    new_entry->iface = iface;
    TAILQ_INSERT_TAIL(&g_installed_protocols, new_entry, entries);
    
    return 0;
}

int
remove_protocol(void)
{
    return 0;
}

int
locate_protocol(EFI_GUID *guid, uint64_t *iface)
{
    DEBUG_MSG("Trying to locate protocol %s", guid_to_string(guid));
    struct protocols_list *tmp_entry = 0;
    TAILQ_FOREACH(tmp_entry, &g_installed_protocols, entries)
    {
        if (memcmp(&tmp_entry->guid, guid, sizeof(EFI_GUID)) == 0)
        {
            DEBUG_MSG("Found protocol!");
            *iface = tmp_entry->iface;
            return 0;
        }
    }

    return -1;
}
