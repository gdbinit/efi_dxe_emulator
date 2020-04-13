#pragma once

#include <unicorn/unicorn.h>

int
UpdateState(uc_engine* uc);

int
sync(uc_engine* uc, const char* target_file);

void
register_sync_cmds(uc_engine* uc);