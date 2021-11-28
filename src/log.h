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

#ifndef __LOG_H
#define __LOG_H

#define LOG_ERROR   0
#define LOG_WARN    1
#define LOG_INF     2
#define LOG_NOTE    3
#define LOG_DBG     4

#define LOG_LEVEL LOG_DBG

#if LOG_LEVEL >= LOG_ERROR
# define log_error(...)  printf("[ERR] " __VA_ARGS__)
#else
# define log_error(...)
#endif

#if LOG_LEVEL >= LOG_WARN
# define log_warn(...)   printf("[WRN] " __VA_ARGS__)
#else
# define log_warn(...)
#endif

#if LOG_LEVEL >= LOG_INF
# define log_info(...)   printf("[INF] "  __VA_ARGS__)
#else
# define log_info(...)
#endif

#if LOG_LEVEL >= LOG_NOTE
# define log_notice(...) printf("[NOTE] " __VA_ARGS__)
#else
# define log_notice(...)
#endif

#if LOG_LEVEL >= LOG_DBG
# define log_debug(...)  printf("[DBG] " __VA_ARGS__)
#else
# define log_debug(...)
#endif

#endif
