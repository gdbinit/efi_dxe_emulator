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
 * cmds.c
 *
 * EFI debugger command line parser and cmd functions
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

#include "cmds.h"

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <string.h>
#include <sys/queue.h>
#include <unicorn/unicorn.h>
#include <linenoise.h>

#include "pe_definitions.h"
#include "efi_definitions.h"
#include "logging.h"
#include "efi_runtime_hooks.h"
#include "efi_boot_hooks.h"
#include "config.h"
#include "nvram.h"
#include "debugger.h"
#include "global_cmds.h"
#include "mem_utils.h"
#include "string_ops.h"

struct cmd_list
{
    char *name;
    uc_engine *uc;
    size_t name_len;
    char *shortcut;
    size_t shortcut_len;
    int (*function)(const char*, uc_engine*);
    char *help;
    TAILQ_ENTRY(cmd_list) entries;
};

TAILQ_HEAD(cmd_list_tailq, cmd_list);

struct cmd_list_tailq g_cmds = TAILQ_HEAD_INITIALIZER(g_cmds);

static int parse_user_cmd(char *exp);

void
completionHook(char const *prefix, linenoiseCompletions *lc)
{
    struct cmd_list *cmd = NULL;
    TAILQ_FOREACH(cmd, &g_cmds, entries)
    {
        if (strncmp(prefix, cmd->name, strlen(prefix)) == 0)
        {
            linenoiseAddCompletion(lc, cmd->name);
        }
    }
}

int
init_linenoise(const char *history_file)
{
    linenoiseInstallWindowChangeHandler();
    linenoiseHistoryLoad(history_file);
    linenoiseSetCompletionCallback(completionHook);
    return 0;
}

int
close_linenoise(const char *history_file)
{
    linenoiseHistorySave(history_file);
    linenoiseHistoryFree();
    return 0;
}

/*
 * user prompt loop
 * waits for user command and lookups installed commands
 * to see if they match, calling its registered callback
 */
int
prompt_loop(void)
{
    static char last_cmd[1024] = {0};
    char const* prompt = "\x1b[31mefi_emu\x1b[0m> ";
    while (1)
    {
        char *result = linenoise(prompt);
        if (result == NULL)
        {
            break;
        }
        /* XXX: this should repeat last command */
        else if (*result == '\0')
        {
            if (*last_cmd == '\0')
            {
                DEBUG_MSG("Last cmd empty");
                free(result);
                continue;
            }
            else
            {
                linenoiseHistoryAdd(result);
                int ret = parse_user_cmd(last_cmd);
                free(result);
                /* a value of zero means no exit of user prompt */
                if (ret == 0)
                {
                    continue;
                }
                /* any other return value the user prompt exits and execution continues */
                else
                {
                    break;
                }
            }
        }
        else
        {
            linenoiseHistoryAdd(result);
            strlcpy(last_cmd, result, sizeof(last_cmd));
            int ret = parse_user_cmd(result);
            free(result);
            if (ret == 0)
            {
                continue;
            }
            else
            {
                break;
            }
        }
    }
    return 0;
}

void
add_user_cmd(char *name, char *shortcut, int (*fun)(const char*, uc_engine *), char *help, uc_engine *uc)
{
    struct cmd_list *cur_cmd = NULL;

    TAILQ_FOREACH(cur_cmd, &g_cmds, entries)
    {
        if (strcmp(name, cur_cmd->name) == 0)
        {
            ERROR_MSG("Command already exists.");
            return;
        }
    }
    
    auto new_cmd = static_cast<struct cmd_list *>(my_malloc(sizeof(struct cmd_list)));    
    new_cmd->name = name;
    new_cmd->name_len = strlen(name);
    new_cmd->function = fun;
    new_cmd->uc = uc;
    new_cmd->help = help;
    new_cmd->shortcut = shortcut;
    new_cmd->shortcut_len = 0;
    if (shortcut != NULL)
    {
        new_cmd->shortcut_len = strlen(shortcut);
    }
    
    TAILQ_INSERT_HEAD(&g_cmds, new_cmd, entries);
    
    return;
}

/*
 * a value of zero means no exit of user prompt
 * any other return value the user prompt exits and execution continues
 */
static int
parse_user_cmd(char *exp)
{
    struct cmd_list *cmd = NULL;
    /* full command first */
    TAILQ_FOREACH(cmd, &g_cmds, entries)
    {
        if (memcmp(exp, cmd->name, cmd->name_len) == 0)
        {
            return cmd->function(exp, cmd->uc);
        }
    }
    /* shortcuts */
    /* XXX: this is hacky because for commands with common part it will execute the first registered hit
     * for example continue and context -> cont will trigger this problem
     */
    TAILQ_FOREACH(cmd, &g_cmds, entries)
    {
        if (cmd->shortcut != NULL && memcmp(exp, cmd->shortcut, cmd->shortcut_len) == 0)
        {
            return cmd->function(exp, cmd->uc);
        }
    }
    return 0;
}

#pragma region Commands functions

int
help_cmd(const char *exp, uc_engine *uc)
{
    char *local_exp = NULL;
    char *local_exp_ptr = NULL;
    local_exp_ptr = local_exp = strdup(exp);
    if (local_exp == NULL)
    {
        ERROR_MSG("strdup failed");
        return 0;
    }
    
    char *token = NULL;
    /* get rid of help string */
    strsep(&local_exp, " ");
    /* extract the help target */
    token = strsep(&local_exp, " ");
    free(local_exp_ptr);
    
    if (token == NULL)
    {
        OUTPUT_MSG("List of commands:\n");
        /* XXX: display help on help itself */
        struct cmd_list *cmd = NULL;
        TAILQ_FOREACH(cmd, &g_cmds, entries)
        {
            char line_buffer[512] = {0};
            uint64_t line_size = 0;
            char *p = cmd->help;
            while (*p && *p != '\n' && *p != '.')
            {
                p++;
            }
            /* add 1 char else strlcpy will strip it */
            line_size = p - cmd->help + 1;
            if (line_size >= sizeof(line_buffer))
            {
                line_size = sizeof(line_buffer);
            }
            strlcpy(line_buffer, cmd->help, line_size);
            OUTPUT_MSG("%s -- %s", cmd->name, line_buffer);
        }
    }
    else
    {
        struct cmd_list *cmd = NULL;
        TAILQ_FOREACH(cmd, &g_cmds, entries)
        {
            if (memcmp(token, cmd->name, cmd->name_len) == 0)
            {
                OUTPUT_MSG("%s", cmd->help);
                return 0;
            }
        }
        
        ERROR_MSG("Unknown command.");
        return 0;
    }
    return 0;
}

int
history_cmd(const char *exp, uc_engine *uc)
{
    /* Display the current history. */
    for (int index = 0; ; ++index)
    {
        char* hist = linenoiseHistoryLine(index);
        if (hist == NULL)
        {
            break;
        }
        OUTPUT_MSG("%4d: %s", index, hist);
        free(hist);
    }
    return 0;
}

#pragma endregion
