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
    //HRESULT hRes;
    //ULONG64 PrevBase = g_Base;
    //ULONG NameSize = 0;

    /*
    msdn: GetInstructionOffset method returns the location of
    the current thread's current instruction.
    */
    uc_err err = uc_reg_read(uc, UC_X86_REG_RIP, &g_Offset);
    if (err != UC_ERR_OK) {
        DEBUG_MSG("[sync] failed to read RIP\n");
        return -1;
    }

    //hRes = g_ExtRegisters->GetInstructionOffset(&g_Offset);
    //if (FAILED(hRes)) {
    //    DEBUG_MSG("[sync] failed to GetInstructionOffset\n");
    //    return hRes;
    //}

    /*
    msdn: GetModuleByOffset method searches through the target's modules for one
    whose memory allocation includes the specified location.
    */
//    hRes = g_ExtSymbols->GetModuleByOffset(g_Offset, 0, NULL, &g_Base);
//    if (FAILED(hRes)) {
//        DEBUG_MSG("[sync] failed to GetModuleByOffset for offset: 0x%I64x\n", g_Offset);
//        return hRes;
//    }
//
//    // Check if we are in a new module
//    if ((g_Base != PrevBase) & g_SyncAuto)
//    {
//        /*
//        Update module name stored in g_NameBuffer
//        msdn: GetModuleNameString  method returns the name of the specified module.
//        */
//        hRes = g_ExtSymbols->GetModuleNameString(DEBUG_MODNAME_LOADED_IMAGE, DEBUG_ANY_ID, g_Base, g_NameBuffer, MAX_NAME, &NameSize);
//        if (SUCCEEDED(hRes)) {
//            if ((NameSize > 0)& (((char)*g_NameBuffer) != 0))
//            {
//#if VERBOSE >= 2
//                DEBUG_MSG("[sync] DEBUG_MODNAME_LOADED_IMAGE: \"%s\"\n", g_NameBuffer);
//#endif
//
//                hRes = TunnelSend("[notice]{\"type\":\"module\",\"path\":\"%s\"}\n", g_NameBuffer);
//                if (FAILED(hRes)) {
//                    return hRes;
//                }
//            }
//        }
//    }
//
    HRESULT hRes = TunnelSend("[notice]{\"type\":\"module\",\"path\":\"%s\"}\n", "PcdDxe");
    hRes = TunnelSend("[sync]{\"type\":\"loc\",\"base\":%llu,\"offset\":%llu}\n", g_Base, g_Offset);
    return (SUCCEEDED(hRes)) ? 0 : -1;
//    return hRes;
}

int
sync(uc_engine *uc)
{
    HRESULT hRes = S_OK;
    PCSTR Host = g_DefaultHost;
    PSTR pszId = NULL;

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
    UpdateState(uc);

Exit:
    if (!(pszId == NULL)) {
        free(pszId);
    }

    return SUCCEEDED(hRes) ? 0 : -1;
}