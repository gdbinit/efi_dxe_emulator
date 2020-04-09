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
 * Created by fG! on 23/04/16.
 * Copyright © 2016-2019 Pedro Vilaca. All rights reserved.
 * reverser@put.as - https://reverse.put.as
 *
 * main.c
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

#include <stdio.h>
#include <getopt.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <mman/sys/mman.h>
#include <string.h>
#include <unistd.h>
#include <string.h>
#include <assert.h>
#include <errno.h>

#include <unicorn/unicorn.h>

#include <linenoise.h>
#include "ini.h"

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
#include "unicorn_hooks.h"
#include "protocols.h"
#include "unicorn_macros.h"
#include "unicorn_utils.h"
#include "mem_utils.h"
#include "guids.h"
#include "sync.h"
#include "events.h"

extern struct bin_images_tailq g_images;
struct configuration g_config;

void
header(void)
{
    printf(
           " ___ ___ ___   _____  _____   ___           _      _\n"
           "| __| __|_ _| |   \\ \\/ / __| | __|_ __ _  _| |__ _| |_ ___ _ _\n"
           "| _|| _| | |  | |) >  <| _|  | _|| '  \\ || | / _` |  _/ _ \\ '_|\n"
           "|___|_| |___| |___/_/\\_\\___| |___|_|_|_\\_,_|_\\__,_|\\__\\___/_|\n"
           "(c) 2016-2019, fG! - reverser@put.as - https://reverse.put.as\n\n"
           "A Unicorn Engine based EFI DXE binaries emulator and debugger\n\n"
           );
}

/*
 * callback that parses the ini file
 */
static int
my_ini_handler(void* user, const char* section, const char* name, const char* value)
{
    if (strcmp(section, "main") == 0)
    {
        if (strcmp(name, "target") == 0)
        {
            g_config.target_file = strdup(value);
        }
        else if (strcmp(name, "nvram") == 0)
        {
            g_config.nvram_file = strdup(value);
        }
        else if (strcmp(name, "guids") == 0)
        {
            g_config.guids_file = strdup(value);
        }
        else if (strcmp(name, "history") == 0)
        {
            g_config.history_file = strdup(value);
        }
        else if (strcmp(name, "serial") == 0)
        {
            g_config.serial_number = strdup(value);
        }
        else if (strcmp(name, "hexedit") == 0)
        {
            g_config.hex_editor = strdup(value);
        }
    }
    else if (strcmp(section, "protocols") == 0)
    {
        auto new_entry = static_cast<struct config_protocols *>(my_malloc(sizeof(struct config_protocols)));
        new_entry->path = strdup(value);
        TAILQ_INSERT_TAIL(&g_config.protos, new_entry, entries);
    }
    return 1;
}

void
help(const char *name)
{
    printf("\n---[ Usage: ]---\n"
           "%s -i ini file [-t EFI binary to emulate -n extracted NVRAM file from UEFITool] [-v]\n\n"
           "Where:\n"
           "-i ini file: path to ini file with emulation configuration\n\n"
           "-v: verbose logging\n"
           "Use these if no ini file is specified\n"
           "-t EFI binary: EFI binary to emulate\n"
           "-n nvram file: path to NVRAM file extracted by UEFITool\n"
           "", name);
}

int
main(int argc, const char * argv[])
{
    header();
    
    // required structure for long options
    static struct option long_options[]={
        { "verbose", no_argument, NULL, 'v' },
        { "target", required_argument, NULL, 't' },
        { "ini", required_argument, NULL, 'i' },
        { "nvram", required_argument, NULL, 'n' },
        { "guids", required_argument, NULL, 'g' },
        { "hexedit", required_argument, NULL, 'x' },
        { NULL, 0, NULL, 0 }
    };
    int option_index = 0;
    int c = 0;
    
    char *target_file = NULL;
    char *nvram_file = NULL;
    char* guids_file = NULL;
    int verbose_mode = 0;
    char *ini_file = NULL;
    char* hex_editor = NULL;
    
    // process command line options
    while ((c = getopt_long (argc, (char * const*)argv, "vt:n:g:i:x:", long_options, &option_index)) != -1)
    {
        switch (c)
        {
            case 'v':
                verbose_mode = 1;
                break;
            case 't':
                target_file = optarg;
                break;
            case 'n':
                nvram_file = optarg;
                break;
            case 'g':
                guids_file = optarg;
                break;
            case 'i':
                ini_file = optarg;
                break;
            case 'x':
                hex_editor = optarg;
                break;
            default:
                break;
        }
    }
    
    set_log_level(verbose_mode);
    
    if (argc < 2)
    {
        help(argv[0]);
        return EXIT_FAILURE;
    }

    /* initialize the tailq that might hold protocols to load */
    TAILQ_INIT(&g_config.protos);

    if (ini_file)
    {
        if (access(ini_file, R_OK) < 0)
        {
            ERROR_MSG("Can't open ini file %s. Error: %s.", ini_file, strerror(errno));
            return EXIT_FAILURE;
        }
        if (ini_parse(ini_file, my_ini_handler, NULL) != 0)
        {
            ERROR_MSG("Failed to parse ini file.");
            return EXIT_FAILURE;
        }
    }

    /* explicit parameters should override the INI file */
    if (target_file) g_config.target_file = target_file;
    if (nvram_file) g_config.nvram_file = nvram_file;
    if (guids_file) g_config.guids_file = guids_file;
    if (hex_editor) g_config.hex_editor = hex_editor;

    if (g_config.target_file == NULL)
    {
        ERROR_MSG("Required target EFI file not found in ini file or command line arguments.");
        return EXIT_FAILURE;
    }
    if (g_config.nvram_file == NULL)
    {
        ERROR_MSG("Required NVRAM file not found in init file or command line arguments.");
        return EXIT_FAILURE;
    }

    /* set a default history file to %USERPROFILE% if not configured in the ini */
    if (g_config.history_file == NULL)
    {
        g_config.history_file = static_cast<char *>(my_calloc(1, MAX_PATH+1));
        snprintf(g_config.history_file, MAX_PATH, "%s\\%s", getenv("USERPROFILE"), HISTORY_FILE);
    }
    
    /* use a default GUIDs file */
    if (g_config.guids_file == NULL)
    {
        g_config.guids_file = GUIDS_FILE;
    }

    if (g_config.hex_editor == NULL)
    {
        WARNING_MSG("Path to hex editor not specified, some commands will not work");
    }
    else
    {
        if (access(g_config.hex_editor, R_OK) < 0)
        {
            WARNING_MSG("Hex editor %s does not exit or not accessible. Error: %s.", g_config.hex_editor, strerror(errno));
        }
    }

    /* and now start the party */

    uc_engine *uc = NULL;
    uc_err err = UC_ERR_OK;
    err = uc_open(UC_ARCH_X86, UC_MODE_64, &uc);
    VERIFY_UC_OPERATION_RET(err, EXIT_FAILURE, "Failed on uc_open()");

    init_linenoise(g_config.history_file);
    register_debugger_cmds(uc);
    register_global_cmds(uc);
    register_breakpoint_cmds(uc);
    register_nvram_cmds(uc);
    
    /* allocate the different memory areas for executables, stack, heap, efi services, etc */
    if (allocate_emulation_mem(uc) != 0)
    {
        ERROR_MSG("Failed to allocate Unicorn memory areas.");
        return EXIT_FAILURE;
    }
    
    /* write the machine serial number if configured */
    if (g_config.serial_number != NULL)
    {
        if (write_serial_number(uc, g_config.serial_number) != 0)
        {
            ERROR_MSG("Failed to write machine serial number.");
            return EXIT_FAILURE;
        }
    }
    OUTPUT_MSG("[+] Loading and mapping main EFI binary...");
    /* this is the main EFI binary we are going to emulate */
    if (load_and_map_main_image(g_config.target_file, uc) != 0)
    {
        ERROR_MSG("Failed to load main binary image.");
        return EXIT_FAILURE;
    }

    /* load and map other images that contain protocols the main binary will be using */
    /* NOTE: protocols must be configured via an ini file */
    if (ini_file != NULL)
    {
        OUTPUT_MSG("[+] Loading and mapping any configured protocols binaries");
        load_and_map_protocols(uc, &g_config.protos);
    }
    /* 
     * NVRAM variables are stored on a buffer outside Unicorn VM memory
     * we then use this inside the variable related functions
     */
    OUTPUT_MSG("[+] Loading NVRAM");
    if (load_nvram(g_config.nvram_file) != 0)
    {
        ERROR_MSG("Failed to load NVRAM file.");
        return EXIT_FAILURE;
    }

    OUTPUT_MSG("[+] Loading GUIDs");
    if (load_guids(g_config.guids_file) != 0)
    {
        WARNING_MSG("Failed to load GUIDs file.");
        /* Not fatal, so don't exit. */
    }
    
    /* 
     * create a fake EFI Boot and RunTime services table
     * that is basically code we intercept and return control into
     * our code so we can emulate the EFI services
     */
    OUTPUT_MSG("[+] Creating EFI service tables...");
    if (create_and_map_efi_system_table(uc) != 0)
    {
        ERROR_MSG("Failed to create EFI system table.");
        return EXIT_FAILURE;
    }
    
    struct bin_image *main_image = TAILQ_FIRST(&g_images);
    assert(main_image != NULL);
    
    OUTPUT_MSG("[+] Configuring Unicorn initial state...");
    /* set the initial registers state */
    uint64_t r_rip = main_image->base_addr + main_image->entrypoint;
    err = uc_reg_write(uc, UC_X86_REG_RIP, &r_rip);
    VERIFY_UC_OPERATION_RET(err, EXIT_FAILURE, "Failed to write initial RIP register");

    uint64_t r_rsp = STACK_ADDRESS + STACK_SIZE/2;
    err = uc_reg_write(uc, UC_X86_REG_RSP, &r_rsp);
    VERIFY_UC_OPERATION_RET(err, EXIT_FAILURE, "Failed to write initial RSP register");

    /* RDX should always point to EFI SYSTEM TABLE address */
    uint64_t r_rdx = EFI_SYSTEM_TABLE_ADDRESS;
    err = uc_reg_write(uc, UC_X86_REG_RDX, &r_rdx);
    VERIFY_UC_OPERATION_RET(err, EXIT_FAILURE, "Failed to write initial RDX register");
    /* RCX is the ImageHandle argument - let's keep it NULL for now */

    if (add_unicorn_hook(uc, UC_HOOK_INTR, hook_interrupt, 1, 0) != 0)
    {
        ERROR_MSG("Failed to add interrupts hook.");
        return EXIT_FAILURE;
    }
    /* add a hook to deal with unmapped memory exceptions */
    if (add_unicorn_hook(uc, UC_HOOK_MEM_UNMAPPED, hook_unmapped_mem, 1, 0) != 0)
    {
        ERROR_MSG("Failed to add unmapped memory hook.");
        return EXIT_FAILURE;
    }

    /* add a hook to deal with invalid instructions exceptions */
    if (add_unicorn_hook(uc, UC_HOOK_INSN_INVALID, hook_invalid_insn, 1, 0) != 0)
    {
        ERROR_MSG("Failed to add invalid instruction hook.");
        return EXIT_FAILURE;
    }
    
    uint64_t total_images = 0;
    struct bin_image *tmp_image = NULL;
    TAILQ_FOREACH(tmp_image, &g_images, entries)
    {
        total_images++;
    }
    OUTPUT_MSG("[+] Total images loaded: %llu", total_images);
    
    /* start emulating the secondary images so they install whatever protocols they support */    
    OUTPUT_MSG("[+] Starting secondary images emulation...");
    struct bin_image *secondary_image = NULL;
    TAILQ_FOREACH(secondary_image, &g_images, entries)
    {
        if (secondary_image->main == 0)
        {
            err = uc_emu_start(uc, secondary_image->tramp_start, secondary_image->tramp_end, 0, 0);
            VERIFY_UC_OPERATION_RET(err, EXIT_FAILURE, "Failed to start Unicorn emulation for %s", secondary_image->file_path);
        }
    }
    
    /* reset Unicorn registers to a clean state before starting emulation of main image */
    initialize_unicorn_registers(uc);
    
    /* reset EFLAGS else we land in some weird bug where test rax,rax will not update EFLAGS for example */
    uint64_t r_eflags = 0x0;
    err = uc_reg_write(uc, UC_X86_REG_EFLAGS, &r_eflags);
    VERIFY_UC_OPERATION_RET(err, EXIT_FAILURE, "Failed to reset RFLAGS");
    
    /* RDX should always point to EFI SYSTEM TABLE address */
    err = uc_reg_write(uc, UC_X86_REG_RDX, &r_rdx);
    VERIFY_UC_OPERATION_RET(err, EXIT_FAILURE, "Failed to reset EFI SYSTEM TABLE register");
    
    /* 
     * allow Unicorn to trace the whole code
     * the reason for this is that we can't really introduce true breakpoints on the code
     * so we trace every single code and fake breakpoints
     * breakpoints are just addresses where we want to stop tracing and prompt a CLI
     * else we just continue execution
     */
    uc_hook entrypoint_trace = 0;
    err = uc_hook_add(uc,
                      &entrypoint_trace,
                      UC_HOOK_CODE,
                      hook_code,
                      NULL,
                      main_image->base_addr + main_image->entrypoint,
                      main_image->base_addr + main_image->entrypoint + main_image->buf_size);
    VERIFY_UC_OPERATION_RET(err, EXIT_FAILURE, "Failed to add main Unicorn code hook.");
    /*
     * we also want to have a chance to trace the EFI services we are emulating
     * there isn't much to trace since the EFI services functions inside Unicorn are just a breakpoint
     * so we can return control to the emulator and emulate the functions
     */
    if (add_unicorn_hook(uc, UC_HOOK_CODE, hook_code, EFI_SYSTEM_TABLE_ADDRESS, EFI_SYSTEM_TABLE_ADDRESS + EFI_SYSTEM_TABLE_SIZE) != 0)
    {
        ERROR_MSG("Failed to add EFI services Unicorn code hook.");
        return EXIT_FAILURE;
    }
    
    /* add breakpoint on entrypoint - we always start the emulator stopped on entrypoint */
    if (add_breakpoint(main_image->base_addr + main_image->entrypoint, 0, kPermBreakpoint, "Entrypoint") != 0)
    {
        ERROR_MSG("Failed to add entrypoint breakpoint.");
        return EXIT_FAILURE;
    }
    
    OUTPUT_MSG("[+] Synching with IDA...");
    if (sync(uc, g_config.target_file) != 0)
    {
        WARNING_MSG("Failed to sync with IDA.");
        /* Non-fatal, don't exit */
    }

    OUTPUT_MSG("[+] Starting main image emulation...");
    err = uc_emu_start(uc, main_image->tramp_start, main_image->tramp_end, 0, 0);
    VERIFY_UC_OPERATION_RET(err, EXIT_FAILURE, "Failed to start Unicorn emulation");

    OUTPUT_MSG("[+] Starting notification routines emulation...");
    dispatch_event_notification_routines(uc);

    OUTPUT_MSG("[+] All done, main image emulation complete.");
    context_cmd("", uc);
    prompt_loop();
    uc_close(uc);
    close_linenoise(g_config.history_file);
    return 0;
}
