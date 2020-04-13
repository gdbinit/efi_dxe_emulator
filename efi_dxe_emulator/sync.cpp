#include "sync.h"
#include "config.h"
#include "logging.h"
#include "tunnel.h"
#include "loader.h"
#include "string_ops.h"
#include "cmds.h"

#include <unicorn/unicorn.h>
#include <sys/queue.h>
#include <stdexcept>

ULONG64 g_Offset = NULL;
ULONG64 g_Base = EXEC_ADDRESS;

// Default host value is locahost
static CHAR* g_DefaultHost = "127.0.0.1";
static CHAR* g_DefaultPort = "9100";

extern struct bin_images_tailq g_images;

static int sync_bc_cmd(const char* exp, uc_engine* uc);

void
register_sync_cmds(uc_engine* uc)
{
    add_user_cmd("bc", NULL, sync_bc_cmd, "Sets background color for sync.\n\nb ADDRESS", uc);
}

static int
sync_bc_cmd(const char *exp, uc_engine *uc)
{
    auto tokens = tokenize(exp);
    //_ASSERT(tokens.at(0) == "bc");

    if (tokens.size() < 2)
    {
        OUTPUT_MSG("Usage error");
        return 0;
    }

    auto mode = tokens.at(1);
    char* rgb_msg[64] = { 0 };
    char* msg;

    if (mode == "on")
    {
        msg = "on";
    }
    else if (mode == "off")
    {
        msg = "off";
    }
    else if (mode == "set")
    {
        uint32_t color = 0;
        try
        {
            color = strtoul(tokens.at(2).c_str(), nullptr, 16);
            color = htonl(color) >> 8;
        }
        catch (const std::out_of_range&)
        {
            OUTPUT_MSG("Invalid color value");
            return 0;
        }
        _snprintf_s((char*)rgb_msg, 64, _TRUNCATE, "%s\", \"rgb\":%lu, \"reserved\":\"", "set", color);
        msg = (char*)rgb_msg;
    }
    else
    {
        OUTPUT_MSG("Invalid mode");
        return 0;
    }

    HRESULT hRes = TunnelSend("[notice]{\"type\":\"bc\",\"msg\":\"%s\",\"base\":%llu,\"offset\":%llu}\n", msg, g_Base, g_Offset);
    return 0;
}

// Update state and send info to client: eip module's base address, offset, name
int
UpdateState(uc_engine *uc)
{
    uc_err err = uc_reg_read(uc, UC_X86_REG_RIP, &g_Offset);
    if (err != UC_ERR_OK) {
        DEBUG_MSG("[sync] failed to read RIP\n");
        return -1;
    }

    HRESULT hRes;

    struct bin_image* current_image = NULL;
    TAILQ_FOREACH(current_image, &g_images, entries)
    {
        if ( (current_image->mapped_addr <= g_Offset) &&
             (g_Offset <= current_image->mapped_addr + current_image->buf_size) )
        {
            g_Base = current_image->mapped_addr;
            hRes = TunnelSend("[notice]{\"type\":\"module\",\"path\":\"%s\"}\n", current_image->file_path);
            if (FAILED(hRes)) {
                goto Exit;
            }
        }
    }

    hRes = TunnelSend("[sync]{\"type\":\"loc\",\"base\":%llu,\"offset\":%llu}\n", g_Base, g_Offset);
    if (FAILED(hRes)) {
        goto Exit;
    }

Exit:
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