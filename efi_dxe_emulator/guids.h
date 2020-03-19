#pragma once

#include "efi_definitions.h"

int
load_guids(char* guids_file);

const char*
get_guid_friendly_name(const EFI_GUID& g);

char*
guid_to_string(EFI_GUID* guid);

EFI_GUID
string_to_guid(const char* str);