#pragma once

#include <unicorn/unicorn.h>
#include "efi_definitions.h"

EFI_EVENT create_efi_event(uc_engine* uc,
    uint32_t Type, EFI_TPL NotifyTpl, EFI_EVENT_NOTIFY NotifyFunction, VOID* NotifyContext);
void signal_efi_event(uc_engine* uc, EFI_EVENT Event);
void dispatch_event_notification_routines(uc_engine* uc);