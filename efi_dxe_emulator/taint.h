#pragma once

#include <list>
#include <map>
#include <capstone/x86.h>

extern std::list<uint64_t> tainted_addresses;
extern std::list<x86_reg> regsTainted;

bool checkAlreadyRegTainted(x86_reg reg);
bool taintReg(x86_reg reg);
bool removeRegTainted(x86_reg reg);
bool removeMemTainted(uint64_t addr);