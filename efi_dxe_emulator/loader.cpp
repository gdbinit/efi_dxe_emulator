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
 * loader.c
 *
 * Functions to load/map/etc EFI binaries into Unicorn
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

#include "loader.h"

#include <stdio.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <mman/sys/mman.h>
#include <string.h>
#include <unistd.h>
#include <string.h>
#include <assert.h>

#include <unicorn/unicorn.h>

#include "pe_definitions.h"
#include "logging.h"
#include "efi_runtime_hooks.h"
#include "efi_boot_hooks.h"
#include "config.h"
#include "nvram.h"
#include "debugger.h"
#include "cmds.h"
#include "global_cmds.h"
#include "breakpoints.h"
#include "unicorn_macros.h"
#include "mem_utils.h"
#include "unicorn_hooks.h"

struct bin_images_tailq g_images = TAILQ_HEAD_INITIALIZER(g_images);

EFI_SYSTEM_TABLE g_efi_table = {0};

#ifndef ALIGN
#define ALIGN(x,t,a)              __ALIGN_MASK(x,(t)(a)-1)
#define __ALIGN_MASK(x,mask)    (((x)+(mask))&~(mask))
#endif
#ifndef MIN
#define    MIN(a,b) (((a)<(b))?(a):(b))
#endif /* MIN */

static int fix_relocations(uc_engine *uc, struct bin_image *image);
static int load_image(char *target_file, int main);
static int map_image_to_emulator(uc_engine *uc, struct bin_image *target_image);
static int load_and_map_other_image(uc_engine *uc, char *image_path);
static int parse_and_validate_PE_image(struct bin_image *target_image);

#pragma region Exported functions

/*
 * load the main EFI binary that will be emulated
 */
int
load_and_map_main_image(char *image_path, uc_engine *uc)
{
    if (load_image(image_path, 1) != 0)
    {
        ERROR_MSG("Failed to load %s.", image_path);
        return -1;
    }
    struct bin_image *main_image = TAILQ_FIRST(&g_images);
    assert(main_image != NULL);
    
    /* don't deal with the two exceptions we found for now */
    /* almost all EFI binaries have this base address except two exceptions found in Apple ROM */
    if (main_image->base_addr != EXEC_ADDRESS)
    {
        ERROR_MSG("Target binary has base address different than 0x%08X.", EXEC_ADDRESS);
        return -1;
    }
    
    main_image->mapped_addr = main_image->base_addr;
    
    /* install a trampoline for this image */
    /* not really used for the main image */
    install_trampoline(uc, main_image->mapped_addr + main_image->entrypoint, &main_image->tramp_start, &main_image->tramp_end);
    
    /* finally copy the image to Unicorn emulation memory */
    if (map_image_to_emulator(uc, main_image) != 0)
    {
        ERROR_MSG("Failed to map image.");
        return -1;
    }
    
    fix_relocations(uc, main_image);
    
    return 0;
}

/*
 * function to load all binaries that install protocols we need
 *
 */
int
load_and_map_protocols(uc_engine *uc, struct config_protocols_tailq *protocols)
{
    struct bin_image *main_image = TAILQ_LAST(&g_images, bin_images_tailq);
    assert(main_image != NULL);
    
    struct config_protocols *tmp_entry = NULL;
    TAILQ_FOREACH(tmp_entry, protocols, entries)
    {
        DEBUG_MSG("Mapping protocol binary: %s", tmp_entry->path);
        load_and_map_other_image(uc, tmp_entry->path);
    }
    
    return 0;
}

/*
 * create a fake EFI system table that can be used by the EFI binary we are emulating
 * the functions inside the table just contain a return
 * but we use Unicorn hooks on each function to gain control outside Unicorn and emulate
 * each EFI service
 */
int
create_and_map_efi_system_table(uc_engine *uc)
{
    uc_err err = UC_ERR_OK;
    
    uint64_t target_addr = EFI_SYSTEM_TABLE_ADDRESS;
    
    /* create the RunTime services table */
    uint64_t runtime_addr = target_addr + sizeof(EFI_SYSTEM_TABLE);
    size_t total_runtime_hooks = 0;
    install_runtime_services(uc, runtime_addr, &total_runtime_hooks);
    
    uint64_t boot_addr = target_addr + sizeof(EFI_SYSTEM_TABLE) + sizeof(EFI_RUNTIME_SERVICES) + total_runtime_hooks * HOOK_SIZE;
    size_t total_boot_hooks = 0;
    install_boot_services(uc, boot_addr, &total_boot_hooks);
    
    g_efi_table.RuntimeServices = (EFI_RUNTIME_SERVICES *)(runtime_addr);
    g_efi_table.BootServices = (EFI_BOOT_SERVICES *)(boot_addr);
    
    err = uc_mem_write(uc, target_addr, (void*)&g_efi_table, sizeof(EFI_SYSTEM_TABLE));
    if (err != UC_ERR_OK)
    {
        ERROR_MSG("Failed to write EFI system table: %d - %s", err, uc_strerror(err));
        return -1;
    }
    
    return 0;
}

#pragma endregion

#pragma region Local functions

/* XXX: assuming target is always 64 bits?
 * Validate and parse the target image, and extract information we will need later on
 */
static int
parse_and_validate_PE_image(struct bin_image *target_image)
{
    IMAGE_DOS_HEADER *dos_header = (IMAGE_DOS_HEADER*)target_image->buf;
    
    DEBUG_MSG("DOS Header Magic value 0x%x", dos_header->e_magic);

    if (dos_header->e_magic == EFI_IMAGE_TE_SIGNATURE)
    {
        ERROR_MSG("TE binaries not supported!");
        return -1;
    }
    else if (dos_header->e_magic != IMAGE_DOS_SIGNATURE)
    {
        ERROR_MSG("Other PE formats not supported!");
        return -1;
    }

    /*
     * the location of the PE header
     * e_lfanew field into the MZ header gives us the location of the PE header
     */
    IMAGE_NT_HEADERS *header = (IMAGE_NT_HEADERS*)(target_image->buf + dos_header->e_lfanew);
    IMAGE_NT_HEADERS64 *header64 = (IMAGE_NT_HEADERS64*)(target_image->buf + dos_header->e_lfanew);
    
    switch (header->Signature)
    {
        case IMAGE_NT_SIGNATURE:
        {
            DEBUG_MSG("Target is PE binary.");
            break;
        }
        default:
        {
            ERROR_MSG("Unsupported PE binary.");
            return -1;
        }
    }

    switch (header->FileHeader.Machine)
    {
        case IMAGE_FILE_MACHINE_I386:
            DEBUG_MSG("Target is 32 bits PE32.");
            break;
        case IMAGE_FILE_MACHINE_AMD64:
            DEBUG_MSG("Target is 64 bits PE32+");
            break;
        default:
            break;
    }

    switch (header->OptionalHeader.Magic)
    {
        case IMAGE_NT_OPTIONAL_HDR32_MAGIC:
        {
            DEBUG_MSG("Optional header is PE32.");
            break;
        }
        case IMAGE_NT_OPTIONAL_HDR64_MAGIC:
        {
            DEBUG_MSG("Optional header is PE32+.");
            DEBUG_MSG("Subsystem is %x", header64->OptionalHeader.Subsystem);
            break;
        }
        default:
        {
            ERROR_MSG("Unknown optional header.");
            return -1;
        }
    }

    DEBUG_MSG("Target PE file contains %d sections.", header->FileHeader.NumberOfSections);
    DEBUG_MSG("File alignment: %d", header64->OptionalHeader.FileAlignment);
    
    size_t total_size = 0;
    if (header->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)
    {
        DEBUG_MSG("Number of sections is %d.", header64->FileHeader.NumberOfSections);
        char *section_start = (char*)header64 + sizeof(IMAGE_NT_HEADERS64);
        IMAGE_SECTION_HEADER *section = (IMAGE_SECTION_HEADER*)section_start;
        for (int i = 0; i < header64->FileHeader.NumberOfSections; i++)
        {
            DEBUG_MSG("Name %s @ 0x%llx VirtualSize: 0x%x RawSize: 0x%x Relocs: %d", section->Name, header64->OptionalHeader.ImageBase + section->VirtualAddress, section->Misc.VirtualSize, section->SizeOfRawData, section->NumberOfRelocations);
            total_size += section->Misc.VirtualSize;
            section = (IMAGE_SECTION_HEADER*)((char*)section + sizeof(IMAGE_SECTION_HEADER));
        }
    }
    
    target_image->nr_sections = header->FileHeader.NumberOfSections;
    target_image->header = (uint8_t*)header64;
    target_image->entrypoint = header64->OptionalHeader.AddressOfEntryPoint;
    target_image->base_addr = header64->OptionalHeader.ImageBase;
    target_image->buf_size = header64->OptionalHeader.SizeOfImage;
    target_image->relocation_info = header64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
    
    DEBUG_MSG("Total size 0x%lx", total_size);
    DEBUG_MSG("Header total size: 0x%x", header64->OptionalHeader.SizeOfCode + header64->OptionalHeader.SizeOfInitializedData + header64->OptionalHeader.SizeOfUninitializedData);
    DEBUG_MSG("Size of image: 0x%x", header64->OptionalHeader.SizeOfImage);
    DEBUG_MSG("Size of headers: 0x%x", header64->OptionalHeader.SizeOfHeaders);
    DEBUG_MSG("Base address: 0x%llx", header64->OptionalHeader.ImageBase);
    DEBUG_MSG("Entry point address: 0x%llx", header64->OptionalHeader.ImageBase + header64->OptionalHeader.AddressOfEntryPoint);
    DEBUG_MSG("PE characterists: 0x%x", header->FileHeader.Characteristics);
    
    return 0;
}

/*
 * entrypoint function to load an image for emulation
 */
static int
load_image(char *target_file, int main)
{
    DEBUG_MSG("Loading %s...", target_file);
    int fd = open(target_file, O_RDONLY);
    if (fd < 0)
    {
        ERROR_MSG("Failed to open target file.");
        return -1;
    }
    
    size_t buf_size = 0;
    struct stat stat_buf = {0};
    if (fstat(fd, &stat_buf) < 0)
    {
        ERROR_MSG("Failed to fstat target file.");
        close(fd);
        return -1;
    }
    buf_size = stat_buf.st_size;
    
    auto new_image = static_cast<struct bin_image *>(my_malloc(sizeof(struct bin_image)));
    new_image->main = main;
    new_image->base_addr = 0;
    new_image->entrypoint = 0;
    new_image->mapped_addr = 0;
    new_image->tramp_start = 0;
    new_image->tramp_end = 0;
    new_image->file_path = target_file;
    new_image->buf_size = buf_size;
    new_image->buf = static_cast<uint8_t *>(mmap(0, buf_size, PROT_READ, MAP_SHARED, fd, 0));
    if (new_image->buf == MAP_FAILED)
    {
        ERROR_MSG("Failed to mmap target file.");
        free(new_image);
        close(fd);
        return -1;
    }
    close(fd);
    
    if (parse_and_validate_PE_image(new_image) != 0)
    {
        ERROR_MSG("Invalid target binary.");
        free(new_image);
        return -1;
    }
    
    /* image is validated so we can add it to our list */
    TAILQ_INSERT_TAIL(&g_images, new_image, entries);
    
    return 0;
}

/*
 * entrypoint function to load all images that are not the main one
 */
static int
load_and_map_other_image(uc_engine *uc, char *image_path)
{
    // given that we are always inserting new images at the end of the queue
    // we can just get last image data to find where to install the next one
    struct bin_image *last_image = TAILQ_LAST(&g_images, bin_images_tailq);
    assert(last_image != NULL);
    
    uint64_t last_img_end = last_image->mapped_addr + last_image->buf_size;
    uint64_t last_aligned = ALIGN(last_img_end, uint64_t, 0x1000);
    
    DEBUG_MSG("Mapping other image to 0x%llx", last_aligned);
    if (load_image(image_path, 0) != 0)
    {
        ERROR_MSG("Failed to load %s.", image_path);
        return -1;
    }
    
    // the new image is now the last in the queue if load_image() was successful
    last_image = TAILQ_LAST(&g_images, bin_images_tailq);
    last_image->mapped_addr = last_aligned;
    /* install trampoline for this image */
    /* we will start executing the image on the trampoline address instead of the entrypoint - check notes for this function */
    install_trampoline(uc, last_image->mapped_addr + last_image->entrypoint, &last_image->tramp_start, &last_image->tramp_end);
    
    if (map_image_to_emulator(uc, last_image) != 0)
    {
        ERROR_MSG("Failed to map %s image.", image_path);
        return -1;
    }
    
    fix_relocations(uc, last_image);
    
    /* we want to be able to debug code in the axillary modules as well */
    if (add_unicorn_hook(uc, UC_HOOK_CODE, hook_code, last_image->mapped_addr, last_image->mapped_addr + last_image->buf_size) != 0)
    {
        ERROR_MSG("Failed to add code hook for module %s.", last_image->file_path);
        return EXIT_FAILURE;
    }

    return 0;
}

/*
 * function to parse target PE binary
 * and map inside Unicorn memory
 */
static int
map_image_to_emulator(uc_engine *uc, struct bin_image *target_image)
{
    uc_err err = UC_ERR_OK;

    /* map header */
    size_t full_hdr_size = sizeof(IMAGE_DOS_HEADER) + sizeof(IMAGE_NT_HEADERS64);
    err = uc_mem_write(uc, target_image->mapped_addr, (void*)target_image->buf, full_hdr_size);
    VERIFY_UC_OPERATION_RET(err, -1, "Failed to write to Unicorn memory")
    
    DEBUG_MSG("Number of sections to map is %d.", target_image->nr_sections);
    unsigned char *section_start = target_image->header + sizeof(IMAGE_NT_HEADERS64);
    IMAGE_SECTION_HEADER *section = (IMAGE_SECTION_HEADER*)section_start;
    for (int i = 0; i < target_image->nr_sections; i++)
    {
        DEBUG_MSG("Mapping section name %s @ 0x%llx VirtualSize: 0x%x RawSize: 0x%x", section->Name, target_image->mapped_addr + section->VirtualAddress, section->Misc.VirtualSize, section->SizeOfRawData);
        
        err = uc_mem_write(uc, target_image->mapped_addr + section->VirtualAddress, (void*)(target_image->buf + section->PointerToRawData), MIN(section->SizeOfRawData, section->Misc.VirtualSize));
        if (err != UC_ERR_OK)
        {
            ERROR_MSG("Failed to write section %s into emulator memory: %s (%d)", section->Name, uc_strerror(err), err);
            return -1;
        }
        section = (IMAGE_SECTION_HEADER*)((char*)section + sizeof(IMAGE_SECTION_HEADER));
    }

    return 0;
}

/*
 * fix relocations entries
 * compatible with fixing the main image which we did not relocate
 * since the delta will be zero for it
 */
static int
fix_relocations(uc_engine *uc, struct bin_image *image)
{
    if (image->relocation_info.VirtualAddress == 0)
    {
        return 0;
    }
    
    uc_err err = UC_ERR_OK;
    
    DEBUG_MSG("Relocation table virtual address: 0x%x size: %d", image->relocation_info.VirtualAddress, image->relocation_info.Size);
    /* this tells us where the reloc section is so we can process relocation information available there */
    uint64_t reloc_start = image->mapped_addr + image->relocation_info.VirtualAddress;
    uint64_t reloc_end = reloc_start + image->relocation_info.Size;
    /* how much did we relocate this image when we mapped in into Unicorn emulation memory */
    uint64_t delta = image->mapped_addr - image->base_addr;
    
    uint64_t current_reloc = reloc_start;
    /*
     * relocation is made by blocks
     * each block contains an header of IMAGE_BASE_RELOCATION type
     * followed by whatever number of blocks given by the header SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)
     */
    while (current_reloc < reloc_end)
    {
        /* the location of the relocation block header */
        IMAGE_BASE_RELOCATION *reloc_hdr = (IMAGE_BASE_RELOCATION*)(image->buf + image->relocation_info.VirtualAddress);
        DEBUG_MSG("Relocation info: 0x%x 0x%x", reloc_hdr->VirtualAddress, reloc_hdr->SizeOfBlock);
        int total_entries = (reloc_hdr->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION))/sizeof(uint16_t);
        DEBUG_MSG("Total relocation entries: %d", total_entries);
        uint16_t *entry_start = (uint16_t*)((char*)reloc_hdr + 8);
        for (int i = 0; i < total_entries; i++)
        {
            /* each entry is like this
             * type: 4 offset: 12
             *
             * so we can find the address where we need to update the relocation by doing
             * base image address + relocation block Virtual Address + offset
             *
             * if type == EFI_IMAGE_REL_BASED_DIR64 the relocation entry is 8 bytes
             *
             */
            uint8_t reloc_type = *entry_start >> 12;
            uint16_t reloc_base = *entry_start & 0xFFF;
            /* for now just handle EFI_IMAGE_REL_BASED_DIR64 relocation type */
            if (reloc_type != EFI_IMAGE_REL_BASED_DIR64)
            {
                ERROR_MSG("Relocation type that we don't know how to handle!");
                return -1;
            }
            
            DEBUG_MSG("Reloc type 0x%x Base 0x%x", reloc_type, reloc_base);
            /* the address where we will have to update the relocation
             * this is an address already inside Unicorn's emulation memory
             */
            uint64_t target_reloc_addr = image->mapped_addr + reloc_hdr->VirtualAddress + reloc_base;
            DEBUG_MSG("mapped relocation addr: 0x%llx", target_reloc_addr);
            DEBUG_MSG("original relocation addr: 0x%llx", target_reloc_addr-delta);
            /* the original relocation value - retrieved from the buffer to avoid reading from Unicorn emulation memory */
            uint64_t original_value = *(uint64_t*)(image->buf + reloc_hdr->VirtualAddress + reloc_base);
            DEBUG_MSG("relocation original value: 0x%llx", original_value);
            /* fix by the delta between original address and where we mapped this binary in Unicorn emulation memory */
            original_value += delta;
            DEBUG_MSG("updated relocation value: 0x%llx", original_value);
            err = uc_mem_write(uc, target_reloc_addr, &original_value, sizeof(original_value));
            if (err != UC_ERR_OK)
            {
                ERROR_MSG("Failed to update relocation entry!");
                return -1;
            }
            /* advance to next relocation entry */
            entry_start++;
        }
        /* advance to next block if it exists */
        current_reloc += reloc_hdr->SizeOfBlock;
    }
    
    return 0;
}

/*
 * a simple trampoline shellcode
 * the reason why we install a trampoline code is that it makes it easier to trace inside Unicorn
 * because we make a call we know where we the module will start and end
 * this is mostly to be applied to other binaries we want to map that implement protocols used by the main binary
 * so we execute them and when they reach the trampoline end we know execution is finished
 */
int
install_trampoline(uc_engine *uc, uint64_t target_addr, uint64_t *tramp_start, uint64_t *tramp_end)
{
    uint8_t shellcode[] =
    "\x48\xB8\x00\x00\x00\x00\x00\x00\x00\x00"  // mov rax, 0x0
    "\xFF\xD0"                                  // call rax
    "\xCC";                                     // INT3 - not to be executed

    static uint64_t current_trampoline_addr = EFI_TRAMPOLINE_ADDRESS;
    if (current_trampoline_addr + sizeof(shellcode) > EFI_TRAMPOLINE_ADDRESS + EFI_TRAMPOLINE_SIZE)
    {
        ERROR_MSG("No space available to install new trampoline.");
        return -1;
    }
    DEBUG_MSG("Current trampoline base address: 0x%llx", current_trampoline_addr);
    DEBUG_MSG("Trampoline target call address: 0x%llx", target_addr);
    memcpy(shellcode + 2, &target_addr, sizeof(uint64_t));
    uc_err err = uc_mem_write(uc, current_trampoline_addr, shellcode, sizeof(shellcode));
    if (err != UC_ERR_OK)
    {
        DEBUG_MSG("Failed to write %d %s", err, uc_strerror(err));
        return -1;
    }
    
    *tramp_start = current_trampoline_addr;
    // remove last byte because we don't want int3 to be executed
    *tramp_end = current_trampoline_addr + sizeof(shellcode) - 1;
    
    current_trampoline_addr += sizeof(shellcode);
    DEBUG_MSG("Installed trampoline at 0x%llx - 0x%llx", *tramp_start, *tramp_end);
    
    return 0;
}

#pragma endregion
