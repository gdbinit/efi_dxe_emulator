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
 * Created by fG! on 26/04/16.
 * Copyright © 2016-2019 Pedro Vilaca. All rights reserved.
 * reverser@put.as - https://reverse.put.as
 *
 * string_ops.c
 *
 * EFI string functions and other string related functions
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
 * Copyright (c) 2004 - 2007, Intel Corporation
 * All rights reserved. This program and the accompanying materials
 * are licensed and made available under the terms and conditions of the BSD License
 * which accompanies this distribution.  The full text of the license may be found at
 * http://opensource.org/licenses/bsd-license.php
 *
 * THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
 * WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.
 *
 */

#include "string_ops.h"

#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include <assert.h>
#include <string.h>
#include <stdlib.h>

#include "logging.h"
#include "mem_utils.h"

UINTN
StrLen(CHAR16 *String)
{
    UINTN Length;
    
    assert(String != NULL);
    
    for (Length = 0; *String != L'\0'; String++, Length++)
    {
    }
    return Length;
}

UINTN
StrSize(CHAR16 *String)
{
    return (StrLen (String) + 1) * sizeof (*String);
}

CHAR8 *
UnicodeStrToAsciiStr(CHAR16 *Source, CHAR8 *Destination)
{
    CHAR8 *ReturnValue;
    
    assert(Destination != NULL);
    
    //
    // ASSERT if Source is long than PcdMaximumUnicodeStringLength.
    // Length tests are performed inside StrLen().
    //
    assert(StrSize (Source) != 0);
    
    //
    // Source and Destination should not overlap
    //
    assert((UINTN) (Destination - (CHAR8 *) Source) >= StrSize (Source));
    assert((UINTN) ((CHAR8 *) Source - Destination) > StrLen (Source));
    
    
    ReturnValue = Destination;
    while (*Source != '\0') {
        //
        // If any Unicode characters in Source contain
        // non-zero value in the upper 8 bits, then ASSERT().
        //
        assert(*Source < 0x100);
        *(Destination++) = (CHAR8) *(Source++);
    }
    
    *Destination = '\0';
        
    return ReturnValue;
}

void
print_unicode_string(CHAR16 *Source)
{
    uint32_t length = StrSize(Source);
    char *string_to_print = my_malloc(length);
    UnicodeStrToAsciiStr(Source, string_to_print);
    OUTPUT_MSG("%s", string_to_print);
    free(string_to_print);
}

char *
get_guid_string(EFI_GUID *guid)
{
    static char guid_str[37] = {0};
    snprintf(guid_str, sizeof(guid_str), "%08X-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X",
             guid->Data1, guid->Data2, guid->Data3,
             guid->Data4[0], guid->Data4[1], guid->Data4[2], guid->Data4[3],
             guid->Data4[4], guid->Data4[5], guid->Data4[6], guid->Data4[7]);
    return guid_str;
}
