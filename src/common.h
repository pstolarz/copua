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

#ifndef __COMMON_H__
#define __COMMON_H__

#include "log.h"

/* preprocessor stringizers */
#define STR(__s) #__s
#define XSTR(__s) STR(__s)

/* preprocessor concatenators */
#define CON(__a, __b) __a##__b
#define XCON(__a, __b) CON(__a, __b)

#define ARR_SZ(__arr) (sizeof(__arr)/sizeof((__arr)[0]))

#ifndef LIB_NAME
# define LIB_NAME       copua
#endif

/**
 * Trim leading and trailing white spaces around string 's' with length *len.
 * Returns pointer to a trimmed string with length written back under len.
 */
const char *strtrim(const char *s, size_t *len);

#endif
