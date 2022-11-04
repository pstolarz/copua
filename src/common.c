/*
 * Copyright (c) 2021 Piotr Stolarz
 * Copua: Lua CoAP library
 *
 * Distributed under the 2-clause BSD License (the License)
 * see accompanying file LICENSE for details.
 *
 * This software is distributed WITHOUT ANY WARRANTY; without even the
 * implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 * See the License for more information.
 */

#include <ctype.h>
#include <stdio.h>

#include "common.h"

const char *strtrim(const char *s, size_t *len)
{
    const char *e = s + *len -1;

    while (s < e) {
        if (isspace(*s)) s++;
        else
        if (isspace(*e)) e--;
        else
        break;
    }
    *len = (e >= s ? e - s + 1 : 0);
    return s;
}
