#pragma once

#include <unicorn/unicorn.h>
#include <map>

#include "efi_definitions.h"

struct EFI_EVENT_IMPL
{
    bool signaled;
    uint64_t notify_routine;
    uint64_t notify_context;
    /* Trampoline for the notification routine */
    uint64_t tramp[2];
};

extern std::map<EFI_EVENT, EFI_EVENT_IMPL> g_events;

EFI_EVENT create_efi_event(uc_engine* uc,
    uint32_t Type, EFI_TPL NotifyTpl, EFI_EVENT_NOTIFY NotifyFunction, VOID* NotifyContext);
void signal_efi_event(uc_engine* uc, EFI_EVENT Event);
void dispatch_event_notification_routines(uc_engine* uc);

