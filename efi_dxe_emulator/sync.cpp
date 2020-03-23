#include "sync.h"
#include "config.h"
#include "logging.h"

#include <unicorn/unicorn.h>
#include "tunnel.h"

ULONG64 g_Offset = NULL;
ULONG64 g_Base = EXEC_ADDRESS;

// Default host value is locahost
static CHAR* g_DefaultHost = "127.0.0.1";
static CHAR* g_DefaultPort = "9100";

// Update state and send info to client: eip module's base address, offset, name
int
UpdateState(uc_engine *uc)
{
    uc_err err = uc_reg_read(uc, UC_X86_REG_RIP, &g_Offset);
    if (err != UC_ERR_OK) {
        DEBUG_MSG("[sync] failed to read RIP\n");
        return -1;
    }

    HRESULT hRes = TunnelSend("[sync]{\"type\":\"loc\",\"base\":%llu,\"offset\":%llu}\n", g_Base, g_Offset);
    return (SUCCEEDED(hRes)) ? 0 : -1;
}

int
sync(uc_engine *uc, const char * target_file)
{
    HRESULT hRes = S_OK;
    PCSTR Host = g_DefaultHost;

    if (FAILED(hRes = TunnelCreate(Host, g_DefaultPort)))
    {
        DEBUG_MSG("[sync] sync failed\n");
        goto Exit;
    }

    DEBUG_MSG("[sync] probing sync\n");

    hRes = TunnelSend("[notice]{\"type\":\"new_dbg\",\"msg\":\"dbg connect - %s\",\"dialect\":\"windbg\"}\n", "EFI DXE Debugger");
    if (FAILED(hRes))
    {
        DEBUG_MSG("[sync] sync aborted\n");
        goto Exit;
    }

    DEBUG_MSG("[sync] sync is now enabled with host %s\n", Host);

    hRes = TunnelSend("[notice]{\"type\":\"module\",\"path\":\"%s\"}\n", target_file);

    UpdateState(uc);

Exit:
    return SUCCEEDED(hRes) ? 0 : -1;
}