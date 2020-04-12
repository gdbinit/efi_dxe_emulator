#include "taint.h"
#include <set>
#include <map>
#include <capstone/x86.h>
#include <iostream>

std::list<uint64_t> tainted_addresses;
std::list<x86_reg> regsTainted;

bool checkAlreadyRegTainted(x86_reg reg)
{
    for (auto i = regsTainted.begin(); i != regsTainted.end(); i++) {
        if (*i == reg) {
            return true;
        }
    }
    return false;
}

bool checkAlreadyMemTainted(uint64_t addr)
{
    for (auto i = tainted_addresses.begin(); i != tainted_addresses.end(); i++) {
        if (*i == addr) {
            return true;
        }
    }
    return false;
}

bool taintReg(x86_reg reg)
{
    if (checkAlreadyRegTainted(reg) == true) {
        //std::cout << "\t\t\t" << reg << " is already tainted" << std::endl;
        return false;
    }

    switch (reg) {

    case X86_REG_RAX:  regsTainted.push_front(X86_REG_RAX);
    case X86_REG_EAX:  regsTainted.push_front(X86_REG_EAX);
    case X86_REG_AX:   regsTainted.push_front(X86_REG_AX);
    case X86_REG_AH:   regsTainted.push_front(X86_REG_AH);
    case X86_REG_AL:   regsTainted.push_front(X86_REG_AL);
        break;

    case X86_REG_RBX:  regsTainted.push_front(X86_REG_RBX);
    case X86_REG_EBX:  regsTainted.push_front(X86_REG_EBX);
    case X86_REG_BX:   regsTainted.push_front(X86_REG_BX);
    case X86_REG_BH:   regsTainted.push_front(X86_REG_BH);
    case X86_REG_BL:   regsTainted.push_front(X86_REG_BL);
        break;

    case X86_REG_RCX:  regsTainted.push_front(X86_REG_RCX);
    case X86_REG_ECX:  regsTainted.push_front(X86_REG_ECX);
    case X86_REG_CX:   regsTainted.push_front(X86_REG_CX);
    case X86_REG_CH:   regsTainted.push_front(X86_REG_CH);
    case X86_REG_CL:   regsTainted.push_front(X86_REG_CL);
        break;

    case X86_REG_RDX:  regsTainted.push_front(X86_REG_RDX);
    case X86_REG_EDX:  regsTainted.push_front(X86_REG_EDX);
    case X86_REG_DX:   regsTainted.push_front(X86_REG_DX);
    case X86_REG_DH:   regsTainted.push_front(X86_REG_DH);
    case X86_REG_DL:   regsTainted.push_front(X86_REG_DL);
        break;

    case X86_REG_RDI:  regsTainted.push_front(X86_REG_RDI);
    case X86_REG_EDI:  regsTainted.push_front(X86_REG_EDI);
    case X86_REG_DI:   regsTainted.push_front(X86_REG_DI);
    case X86_REG_DIL:  regsTainted.push_front(X86_REG_DIL);
        break;

    case X86_REG_RSI:  regsTainted.push_front(X86_REG_RSI);
    case X86_REG_ESI:  regsTainted.push_front(X86_REG_ESI);
    case X86_REG_SI:   regsTainted.push_front(X86_REG_SI);
    case X86_REG_SIL:  regsTainted.push_front(X86_REG_SIL);
        break;

    default:
        //std::cout << "\t\t\t" << reg << " can't be tainted" << std::endl;
        return false;
    }
    //std::cout << "\t\t\t" << reg << " is now tainted" << std::endl;
    return true;
}

bool removeRegTainted(x86_reg reg)
{
    /*if (!checkAlreadyRegTainted(reg))
    {
        return false;
    }*/

    auto size1 = regsTainted.size();

    switch (reg) {
    case X86_REG_RAX:  regsTainted.remove(X86_REG_RAX);
    case X86_REG_EAX:  regsTainted.remove(X86_REG_EAX);
    case X86_REG_AX:   regsTainted.remove(X86_REG_AX);
    case X86_REG_AH:   regsTainted.remove(X86_REG_AH);
    case X86_REG_AL:   regsTainted.remove(X86_REG_AL);
        break;

    case X86_REG_RBX:  regsTainted.remove(X86_REG_RBX);
    case X86_REG_EBX:  regsTainted.remove(X86_REG_EBX);
    case X86_REG_BX:   regsTainted.remove(X86_REG_BX);
    case X86_REG_BH:   regsTainted.remove(X86_REG_BH);
    case X86_REG_BL:   regsTainted.remove(X86_REG_BL);
        break;

    case X86_REG_RCX:  regsTainted.remove(X86_REG_RCX);
    case X86_REG_ECX:  regsTainted.remove(X86_REG_ECX);
    case X86_REG_CX:   regsTainted.remove(X86_REG_CX);
    case X86_REG_CH:   regsTainted.remove(X86_REG_CH);
    case X86_REG_CL:   regsTainted.remove(X86_REG_CL);
        break;

    case X86_REG_RDX:  regsTainted.remove(X86_REG_RDX);
    case X86_REG_EDX:  regsTainted.remove(X86_REG_EDX);
    case X86_REG_DX:   regsTainted.remove(X86_REG_DX);
    case X86_REG_DH:   regsTainted.remove(X86_REG_DH);
    case X86_REG_DL:   regsTainted.remove(X86_REG_DL);
        break;

    case X86_REG_RDI:  regsTainted.remove(X86_REG_RDI);
    case X86_REG_EDI:  regsTainted.remove(X86_REG_EDI);
    case X86_REG_DI:   regsTainted.remove(X86_REG_DI);
    case X86_REG_DIL:  regsTainted.remove(X86_REG_DIL);
        break;

    case X86_REG_RSI:  regsTainted.remove(X86_REG_RSI);
    case X86_REG_ESI:  regsTainted.remove(X86_REG_ESI);
    case X86_REG_SI:   regsTainted.remove(X86_REG_SI);
    case X86_REG_SIL:  regsTainted.remove(X86_REG_SIL);
        break;

    case X86_REG_RBP:  regsTainted.remove(X86_REG_RBP);
    case X86_REG_EBP:  regsTainted.remove(X86_REG_EBP);
    case X86_REG_BP:   regsTainted.remove(X86_REG_BP);
    case X86_REG_BPL:  regsTainted.remove(X86_REG_BPL);
        break;

    case X86_REG_R8:   regsTainted.remove(X86_REG_R8);
    case X86_REG_R8D:  regsTainted.remove(X86_REG_R8D);
    case X86_REG_R8W:  regsTainted.remove(X86_REG_R8W);
    case X86_REG_R8B:  regsTainted.remove(X86_REG_R8B);
        break;

    case X86_REG_R9:   regsTainted.remove(X86_REG_R9);
    case X86_REG_R9D:  regsTainted.remove(X86_REG_R9D);
    case X86_REG_R9W:  regsTainted.remove(X86_REG_R9W);
    case X86_REG_R9B:  regsTainted.remove(X86_REG_R9B);
        break;

    case X86_REG_R10:   regsTainted.remove(X86_REG_R10);
    case X86_REG_R10D:  regsTainted.remove(X86_REG_R10D);
    case X86_REG_R10W:  regsTainted.remove(X86_REG_R10W);
    case X86_REG_R10B:  regsTainted.remove(X86_REG_R10B);
        break;

    case X86_REG_R11:   regsTainted.remove(X86_REG_R11);
    case X86_REG_R11D:  regsTainted.remove(X86_REG_R11D);
    case X86_REG_R11W:  regsTainted.remove(X86_REG_R11W);
    case X86_REG_R11B:  regsTainted.remove(X86_REG_R11B);
        break;

    case X86_REG_R12:   regsTainted.remove(X86_REG_R12);
    case X86_REG_R12D:  regsTainted.remove(X86_REG_R12D);
    case X86_REG_R12W:  regsTainted.remove(X86_REG_R12W);
    case X86_REG_R12B:  regsTainted.remove(X86_REG_R12B);
        break;

    case X86_REG_R13:   regsTainted.remove(X86_REG_R13);
    case X86_REG_R13D:  regsTainted.remove(X86_REG_R13D);
    case X86_REG_R13W:  regsTainted.remove(X86_REG_R13W);
    case X86_REG_R13B:  regsTainted.remove(X86_REG_R13B);
        break;

    case X86_REG_R14:   regsTainted.remove(X86_REG_R14);
    case X86_REG_R14D:  regsTainted.remove(X86_REG_R14D);
    case X86_REG_R14W:  regsTainted.remove(X86_REG_R14W);
    case X86_REG_R14B:  regsTainted.remove(X86_REG_R14B);
        break;

    case X86_REG_R15:   regsTainted.remove(X86_REG_R15);
    case X86_REG_R15D:  regsTainted.remove(X86_REG_R15D);
    case X86_REG_R15W:  regsTainted.remove(X86_REG_R15W);
    case X86_REG_R15B:  regsTainted.remove(X86_REG_R15B);
        break;

    default:
        return false;
    }
    //std::cout << "\t\t\t" << reg << " is now freed" << std::endl;
    auto size2 = regsTainted.size();
    return (size2 != size1); // indication that we actually removed a tainted register
}

bool removeMemTainted(uint64_t addr)
{
    if (!checkAlreadyMemTainted(addr))
    {
        return false;
    }

    tainted_addresses.remove(addr);
    return true;
}