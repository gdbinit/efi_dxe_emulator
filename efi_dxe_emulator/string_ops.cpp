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
#include <string>
#include <codecvt>
#include <locale>
#include <vector>
#include <sstream>
#include <iostream>

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
    auto string_to_print = static_cast<char *>(my_malloc(length));
    UnicodeStrToAsciiStr(Source, string_to_print);
    OUTPUT_MSG("%s", string_to_print);
    free(string_to_print);
}

char *
strsep(char **stringp, const char *delim)
{
    char* begin, * end;
    begin = *stringp;
    if (begin == NULL)
        return NULL;
    /* Find the end of the token.  */
    end = begin + strcspn(begin, delim);
    if (*end)
    {
        /* Terminate the token and set *STRINGP past NUL character.  */
        *end++ = '\0';
        *stringp = end;
    }
    else
        /* No more delimiters; this is the last token.  */
        *stringp = NULL;
    return begin;
}

size_t
strlcpy(char *dst, const char *src, size_t siz)
{
    char* d = dst;
    const char* s = src;
    size_t n = siz;
    /* Copy as many bytes as will fit */
    if (n != 0) {
        while (--n != 0) {
            if ((*d++ = *s++) == '\0')
                break;
        }
    }
    /* Not enough room in dst, add NUL and traverse rest of src */
    if (n == 0) {
        if (siz != 0)
            *d = '\0';		/* NUL-terminate dst */
        while (*s++)
            ;
    }
    return(s - src - 1);	/* count does not include NUL */
}

using convert_t = std::codecvt_utf8<wchar_t>;
static std::wstring_convert<convert_t, wchar_t> strconverter;

std::string to_string(const std::wstring& wstr)
{
    return strconverter.to_bytes(wstr);
}

std::wstring to_wstring(const std::string& str)
{
    return strconverter.from_bytes(str);
}

std::vector<std::string> tokenize(const char* str, char sep /* = ' ' */)
{
    std::vector<std::string> tokens;

    std::stringstream ss(str);
    std::string tmp;

    while (std::getline(ss, tmp, sep))
    {
        tokens.push_back(tmp);
    }

    return tokens;
}
