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

#include <assert.h>
#include <errno.h>
#include <string.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>

#include "coap2/coap.h"
#include "lua.h"
#include "lauxlib.h"

#include "common.h"


/* default value if not configured otherwise */
#ifndef MAX_COAP_PDU_SIZE
# define MAX_COAP_PDU_SIZE   1152
#endif

#define MOD_NAME            LIB_NAME
#define MOD_NAME_STR        XSTR(MOD_NAME)

#define MOD_INIT_NAME       XCON(luaopen_, MOD_NAME)
#define MOD_INIT_SCRIPT_HDR XCON(MOD_NAME, _init.lua.h)

/* default handlers */
#define REQ_HANDLER   "coap_req_handler"
#define RESP_HANDLER  "coap_resp_handler"
#define NACK_HANDLER  "coap_nack_handler"

/* library metatables */
#define MT_CONTEXT    MOD_NAME_STR ".ctx"
#define MT_PDU        MOD_NAME_STR ".pdu"
#define MT_CONNECTION MOD_NAME_STR ".conn"


typedef enum
{
    OPTVAL_UNKNWN = 0,
    OPTVAL_UINT,
    OPTVAL_STRING,
    OPTVAL_OPAQUE
} coap_optval_type_t;

/* library context */
typedef struct
{
    /* configuration */
    struct {
        size_t max_pdu_sz;
    } cfg;

    /* Lua handlers references (LUA_NOREF for default handler) */
    struct {
        int reqh;
        int resph;
        int nackh;
    } ref;

    /* libcoap specific */
    struct {
        coap_context_t  *ctx;
        coap_endpoint_t *ep;    /* CoAP server endpoint */
        coap_resource_t *rsrc;
    } coap;
} lib_ctx_t;

#define ACS_NO_HNDLR    0U
#define ACS_REQ_HNDLR   1U
#define ACS_RESP_HNDLR  2U
#define ACS_NACK_HNDLR  3U

/* CoAP PDU userdata object (request/response) */
typedef struct
{
    coap_pdu_t *pdu;

    /* associated session; NULL for no session */
    coap_session_t *session;

    /* default CoAP code if not provided, EMPTY(0): not used */
    int def_code;

    /* object access mode */
    struct {
        unsigned ro:    1; /* read-only */
        unsigned lck:   1; /* locked; can not be accessed anymore */
        unsigned hndlr: 3; /* object associated with a specific handler */
    } access;
} ud_coap_pdu_t;

/* connection userdata object */
typedef struct
{
    coap_session_t *session;

    /* the object shall be garbage collected flag */
    int gc;
} ud_connection_t;

#define MAX_QSTR_PARAMS_ARGS 10

/* CoAP query string parameter iteration state */
typedef struct
{
    int n_refs;
    /* references to iterated parameter names */
    int refs[MAX_QSTR_PARAMS_ARGS];

    coap_opt_iterator_t iter;
} coap_qstr_param_iter_state_t;


/* get the library context */
static lib_ctx_t *_get_lib_ctx(lua_State *L)
{
    lib_ctx_t *lib_ctx = NULL;

    lua_pushstring(L, MT_CONTEXT);
    lua_gettable(L, LUA_REGISTRYINDEX);

    lib_ctx = (lib_ctx_t*)lua_touserdata(L, -1);
    if (!lib_ctx)
        luaL_error(L, "No library context in registry");

    lua_pop(L, 1);

    return lib_ctx;
}

/* get object (userdata pointer) of its running method (C-closure) */
static void *_get_self(lua_State *L, int *arg_base)
{
    void *obj;
    int ab = 0;

    obj = lua_touserdata(L, lua_upvalueindex(1));
    if (!obj)
        luaL_error(L, "Invalid call context");

    /* The library accepts both syntaxes of call: obj.method() and obj:method().
       Therefore in case the latter is used ignore the 1st argument (object
       reference) from the arguments list since the reference is taken from
       the C-closure upvalue set by the method's dispatcher. */
    if (lua_gettop(L) >= 1 &&
        lua_type(L, 1) == LUA_TUSERDATA && obj == lua_touserdata(L, 1))
    {
        ab++;
    }

    if (arg_base) *arg_base = ab;
    return obj;
}

/* log CoAP PDU */
static void _log_pdu(
    int level, const char *hndlr_name, coap_pdu_t *pdu, int recv)
{
    int logl;

    if (LOG_LEVEL >= level) {
        log_info("(%s) %s ", hndlr_name, (recv ? "-> " : "<- "));
        logl = coap_get_log_level();
        coap_set_log_level(LOG_INFO);
        coap_show_pdu(LOG_INFO, pdu);
        coap_set_log_level(logl);
    }
}

/**
 * Get CoAP message type.
 *
 * Lua arguments: None
 *
 * Lua return:
 *     type [int]: CoAP message type.
 */
int l_coap_pdu_get_type(lua_State *L)
{
    coap_pdu_t *pdu = ((ud_coap_pdu_t*)_get_self(L, NULL))->pdu;
    lua_pushinteger(L, pdu->type & 3);
    return 1;
}

/**
 * Set CoAP message type.
 *
 * Lua arguments:
 *     type [int]: CoAP message type.
 *
 * Lua return: None
 */
int l_coap_pdu_set_type(lua_State *L)
{
    int arg_base;
    coap_pdu_t *pdu = ((ud_coap_pdu_t*)_get_self(L, &arg_base))->pdu;
    pdu->type = luaL_checkinteger(L, arg_base+1) & 3;
    return 0;
}

/**
 * Get CoAP message code.
 *
 * Lua arguments: None
 *
 * Lua return:
 *     code [int]: CoAP message code.
 */
int l_coap_pdu_get_code(lua_State *L)
{
    coap_pdu_t *pdu = ((ud_coap_pdu_t*)_get_self(L, NULL))->pdu;
    lua_pushinteger(L, 100 * (pdu->code >> 5)  + (pdu->code & 0x1f));
    return 1;
}

/**
 * Set CoAP message code.
 *
 * Lua arguments:
 *     code [int]: CoAP message code.
 *
 * Lua return: None
 */
int l_coap_pdu_set_code(lua_State *L)
{
    int arg_base, code;
    coap_pdu_t *pdu = ((ud_coap_pdu_t*)_get_self(L, &arg_base))->pdu;
    code = luaL_checkinteger(L, arg_base+1);
    pdu->code = COAP_RESPONSE_CODE(code);
    return 0;
}

/**
 * Get CoAP message id.
 *
 * Lua arguments: None
 *
 * Lua return:
 *     id [int]: CoAP message id.
 */
int l_coap_pdu_get_msg_id(lua_State *L)
{
    coap_pdu_t *pdu = ((ud_coap_pdu_t*)_get_self(L, NULL))->pdu;
    lua_pushinteger(L, pdu->tid);
    return 1;
}

/**
 * Set CoAP message id.
 *
 * Lua arguments:
 *     id [int]: CoAP message id.
 *
 * Lua return: None
 */
int l_coap_pdu_set_msg_id(lua_State *L)
{
    int arg_base, msg_id;
    coap_pdu_t *pdu = ((ud_coap_pdu_t*)_get_self(L, &arg_base))->pdu;
    msg_id = luaL_checkinteger(L, arg_base+1);
    pdu->tid = (uint16_t)msg_id;
    return 0;
}

/**
 * Get CoAP message token.
 *
 * NOTE: For performance reason for string token it's always better to use
 *     get_token(false).
 *
 * Lua arguments:
 *     as_arr [bool|none]: If true return token as bytes-array, false - as
 *         string (default if not provided).
 *
 * Lua return:
 *     payload [nil|string|bytes-array (1-based)] Token. nil for no token.
 */
int l_coap_pdu_get_token(lua_State *L)
{
    int arg_base, as_arr = 0;
    coap_pdu_t *pdu = ((ud_coap_pdu_t*)_get_self(L, &arg_base))->pdu;
    size_t i, len = pdu->token_length;
    uint8_t *token = pdu->token;

    if (lua_gettop(L) >= arg_base+1)
        as_arr = lua_toboolean(L, arg_base+1);

    if (!len || !token) {
        lua_pushnil(L);
        return 1;
    }

    if (as_arr) {
        lua_createtable(L, len, 0);
        for (i = 0; i < len; i++) {
            lua_pushinteger(L, token[i]);
            lua_rawseti(L, -2, i+1);
        }
    } else {
        lua_pushlstring(L, (const char*)token, len);
    }
    return 1;
}

/**
 * Set CoAP message token.
 *
 * NOTE: Due to libcoap library constraints token must be added before CoAP
 *     options. Otherwise the library fails.
 * NOTE: Passing payload as bytes-array should be avoided due to its performance
 *     penalty.
 *
 * Lua arguments:
 *     token [string|bytes-array (1-based)|none] Token to be set. No token if
 *         the argument is not provided.
 *
 * Lua return: None
 */
int l_coap_pdu_set_token(lua_State *L)
{
    int arg_base;
    size_t i, len = 0;
    uint8_t *token = NULL;
    uint8_t tkn[8];
    coap_pdu_t *pdu = ((ud_coap_pdu_t*)_get_self(L, &arg_base))->pdu;

    if (lua_type(L, arg_base+1) == LUA_TSTRING) {
        len = luaL_len(L, arg_base+1);
        token = (uint8_t*)lua_tostring(L, arg_base+1);
    } else
    if (lua_type(L, arg_base+1) == LUA_TTABLE)
    {
        len = luaL_len(L, arg_base+1);
        token = tkn;

        if (len > 0 && len <= sizeof(tkn)) {
            for (i = 0; i < len; i++) {
                if (lua_rawgeti(L, arg_base+1, i+1) != LUA_TNUMBER) {
                    return luaL_error(L,
                        "Invalid argument: bytes-array expected");
                }
                tkn[i] = (uint8_t)lua_tointeger(L, -1);
                lua_pop(L, 1);
            }
        }
    } else
    if (lua_gettop(L) >= arg_base+1)
        return luaL_error(L, "Invalid argument passed");

    if (len > sizeof(tkn))
        return luaL_error(L, "Token must be 8 bytes long max");

    if (!coap_add_token(pdu, len, token)) {
        return luaL_error(L,
            "coap_add_token() failed; check order of adding the token");
    }
    return 0;
}

/* get CoAP option value type */
static coap_optval_type_t _get_coap_optval_type(int opt_type)
{
    switch (opt_type)
    {
    case COAP_OPTION_IF_NONE_MATCH:
    case COAP_OPTION_OBSERVE:
    case COAP_OPTION_URI_PORT:
    case COAP_OPTION_CONTENT_FORMAT:
    case COAP_OPTION_MAXAGE:
    case COAP_OPTION_ACCEPT:
    case COAP_OPTION_BLOCK2:
    case COAP_OPTION_BLOCK1:
    case COAP_OPTION_SIZE2:
    case COAP_OPTION_SIZE1:
    case COAP_OPTION_NORESPONSE:
        return OPTVAL_UINT;

    case COAP_OPTION_URI_HOST:
    case COAP_OPTION_LOCATION_PATH:
    case COAP_OPTION_URI_PATH:
    case COAP_OPTION_URI_QUERY:
    case COAP_OPTION_LOCATION_QUERY:
    case COAP_OPTION_PROXY_URI:
    case COAP_OPTION_PROXY_SCHEME:
        return OPTVAL_STRING;

    case COAP_OPTION_IF_MATCH:
    case COAP_OPTION_ETAG:
        return OPTVAL_OPAQUE;

    default:;
    }

    return OPTVAL_UNKNWN;
}

/* push CoAP option's value on the stack */
static void _push_coap_opt_val(lua_State *L, coap_opt_t *opt, int opt_type)
{
    int i;
    const uint8_t *opt_val = coap_opt_value(opt);
    uint16_t opt_len = coap_opt_length(opt);

    /* if the option has no value return nil */
    if (!opt_len) {
        lua_pushnil(L);
        return;
    }

    /* push option value depending on its value type */
    switch (_get_coap_optval_type(opt_type))
    {
    case OPTVAL_UINT:
      {
        uint32_t v = 0;

        for (i = 0; i < opt_len; i++)
            v = (v << 8) | opt_val[i];

        lua_pushinteger(L, v);
        break;
      }

    case OPTVAL_STRING:
      {
        lua_pushlstring(L, (const char*)opt_val, opt_len);
        break;
      }

    /* opaque (raw data) represented by an integer indexed array */
    case OPTVAL_OPAQUE:
    case OPTVAL_UNKNWN:
      {
          lua_createtable(L, opt_len, 0);
          for (i = 0; i < opt_len; i++) {
              lua_pushinteger(L, opt_val[i]);
              lua_rawseti(L, -2, i+1);
          }
          break;
      }
    }
    return;
}

/* CoAP options iteration-function */
static int _coap_option_iter(lua_State *L)
{
    coap_opt_t *opt;

    /* get passed iteration state and the control var */
    coap_opt_iterator_t *opt_iter = (coap_opt_iterator_t*)lua_touserdata(L, 1);
    if (!opt_iter)
        return luaL_argerror(L, 1, "Invalid iterator call");

    if (opt_iter->bad || !(opt = coap_option_next(opt_iter)))
    {
        /* iteration finished */
        lua_pushnil(L);
        return 1;
    }

    /* 1st returned value: option type */
    lua_pushinteger(L, opt_iter->type);

    /* 2nd returned value: option value */
    _push_coap_opt_val(L, opt, opt_iter->type);

    return 2;
}

/**
 * CoAP options iterator.
 *
 * Lua arguments:
 *     opt_type(s) [int(s)|none]: 0 or more option types to obtain. If not
 *         provided all options are taken into account.
 *
 * Lua return:
 *     next [C function]: Options iteration-function.
 *     state [userdata]: Iteration state (coap_opt_iterator_t struct).
 *     cv_init [nil]: Init control variable value (not used).
 */
int l_coap_pdu_options(lua_State *L)
{
    int arg_base, i, n_args;
    coap_pdu_t *pdu = ((ud_coap_pdu_t*)_get_self(L, &arg_base))->pdu;

    coap_opt_filter_t filter;
    coap_option_filter_clear(filter);

    n_args = lua_gettop(L) - arg_base;
    for (i = 0; i < n_args; i++) {
        int opt_type = luaL_checkinteger(L, arg_base+i+1);
        coap_option_filter_set(filter, opt_type);
    }

    /* options iteration-function */
    lua_pushcfunction(L, _coap_option_iter);

    /* iteration state */
    coap_opt_iterator_t *opt_iter =
        lua_newuserdata(L, sizeof(coap_opt_iterator_t));
    coap_option_iterator_init(pdu, opt_iter, (!n_args ? COAP_OPT_ALL : filter));

    /* init control variable value (not used) */
    lua_pushnil(L);

    /* no closing value returned (4th parameter absent) */
    return 3;
}

/**
 * Get CoAP option.
 *
 * NOTE: In case an option has many values the first one is returned. To
 *     obtain all values of a given option the options iterator shall be used.
 *
 * Lua arguments:
 *     opt_type [int]: Option type.
 *
 * Lua return:
 *     value [nil|int|string|bytes-array (1-based)]: nil is returned in case
 *         option value is empty or option doesn't exists. Next returned value
 *         allows to distinguish between these cases.
 *     exist [bool]: true in case option exists, false otherwise.
 */
int l_coap_pdu_get_option(lua_State *L)
{
    int arg_base, opt_type;
    coap_pdu_t *pdu = ((ud_coap_pdu_t*)_get_self(L, &arg_base))->pdu;

    coap_opt_t *opt;
    coap_opt_iterator_t oi;

    coap_opt_filter_t filter;
    coap_option_filter_clear(filter);

    opt_type = luaL_checkinteger(L, arg_base+1);
    coap_option_filter_set(filter, opt_type);

    if (coap_option_iterator_init(pdu, &oi, filter)) {
        for (opt = coap_option_next(&oi); opt; opt = coap_option_next(&oi)) {
            _push_coap_opt_val(L, opt, opt_type);
            lua_pushboolean(L, 1);
            return 2;
        }
    }

    lua_pushnil(L);
    lua_pushboolean(L, 0);
    return 2;
}

/**
 * Set CoAP option.
 *
 * NOTE: Due to libcoap library constraints added options must be set in
 *     ascending option type order, e.g. if required If-Match must be set 1st
 *     as the option with type 1, Uri-Host 2nd etc.
 *
 * Lua arguments:
 *     opt_type [int]: Option type to be set.
 *     opt_val [none|int|string|bytes-array (1-based)]: Option value (depends on
 *         the option type being set). To send option with an empty value omit
 *         the argument.
 *
 * Lua return: None
 */
int l_coap_pdu_set_option(lua_State *L)
{
    int i, j, opt_type, arg_base;
    const uint8_t *opt_val = NULL;
    size_t opt_len = 0;
    uint8_t val_b[255];
    coap_pdu_t *pdu = ((ud_coap_pdu_t*)_get_self(L, &arg_base))->pdu;

    opt_type = luaL_checkinteger(L, arg_base+1);
    if (lua_gettop(L) >= arg_base+2)
    {
        coap_optval_type_t optval_type = _get_coap_optval_type(opt_type);

        if (optval_type == OPTVAL_UNKNWN)
        {
            /* for option of unknown type deduce the type from the passed arg */
            switch (lua_type(L, arg_base+2))
            {
            case LUA_TNUMBER:
                optval_type = OPTVAL_UINT;
                break;
            case LUA_TSTRING:
                optval_type = OPTVAL_STRING;
                break;
            case LUA_TTABLE:
                optval_type = OPTVAL_OPAQUE;
                break;
            default:
                return luaL_error(L, "Invalid argument: "
                    "number, string or bytes-array expected as an option value");
            }
        }

        switch (optval_type)
        {
        case OPTVAL_UINT:
          {
            uint32_t val_i = luaL_checkinteger(L, arg_base+2);

            opt_val = val_b;
            opt_len = sizeof(val_i);

            /* convert to network order */
            for (i = (int)(opt_len-1), j = 0; i >= 0; i--, j++) {
                val_b[j] = (uint8_t)((val_i >> (i << 3)) & 0xff);
            }

            /* cut leading zeroes */
            for (; !*opt_val && opt_len > 1; opt_val++, opt_len--);
            break;
          }

        case OPTVAL_STRING:
          {
            opt_val = (const uint8_t*)luaL_checkstring(L, arg_base+2);
            opt_len = luaL_len(L, arg_base+2);
            break;
          }

        case OPTVAL_OPAQUE:
          {
            luaL_checktype(L, arg_base+2, LUA_TTABLE);

            opt_len = luaL_len(L, arg_base+2);
            if (opt_len > sizeof(val_b)) {
                return luaL_error(L, "Invalid argument: "
                    "array size larger than %d bytes", (int)sizeof(val_b));
            }

            for (i = 0; i < opt_len; i++) {
                if (lua_rawgeti(L, arg_base+2, i+1) != LUA_TNUMBER) {
                    return luaL_error(L,
                        "Invalid argument: bytes-array expected");
                }
                val_b[i] = (uint8_t)lua_tointeger(L, -1);
                lua_pop(L, 1);
            }

            opt_val = val_b;
            break;
          }

        default:;
        }
    } else {
        /* option with an empty value */
    }

    if (!coap_add_option(pdu, opt_type, opt_len, opt_val)) {
        return luaL_error(L,
            "coap_add_option() failed; check order of added options");
    }
    return 0;
}

/**
 * Get CoAP URI path.
 *
 * Lua arguments:
 *     as_arr [bool|none]: If true return Uri_path as strings-array of
 *     Uri-Path options, false - return as single string (default if not
 *     provided). E.g.: "/a/b/c" (string), {"a", "b", "c"} (strings-array).
 *
 * Lua return:
 *     uri_path [nil|string|strings-array (1-based)] nil is returned in case
 *         Uri-Path absence.
 */
int l_coap_pdu_get_uri_path(lua_State *L)
{
    int i, arg_base, as_arr = 0;
    coap_pdu_t *pdu = ((ud_coap_pdu_t*)_get_self(L, &arg_base))->pdu;

    coap_opt_t *opt;
    const char *opt_val;
    uint16_t opt_len;
    coap_opt_iterator_t oi;

    coap_opt_filter_t filter;
    coap_option_filter_clear(filter);
    coap_option_filter_set(filter, COAP_OPTION_URI_PATH);

    if (!coap_option_iterator_init(pdu, &oi, filter))
    {
        /* no options in PDU */
        lua_pushnil(L);
        return 1;
    }

    if (lua_gettop(L) >= arg_base+1)
        as_arr = lua_toboolean(L, arg_base+1);

    if (as_arr) {
        lua_newtable(L);

        for (opt=coap_option_next(&oi), i=0;
            opt; opt=coap_option_next(&oi), i++)
        {
            opt_len = coap_opt_length(opt);
            opt_val = (const char*)coap_opt_value(opt);

            if (opt_len > 0 && opt_val) {
                lua_pushlstring(L, opt_val, opt_len);
                lua_rawseti(L, -2, i+1);
            }
        }

        if (!i) {
            lua_pop(L, 1);
            lua_pushnil(L);
        }
    } else {
        char *str = alloca(pdu->used_size);
        size_t str_len = 0;

        if (!str) return luaL_error(L, "No memory");

        for (opt=coap_option_next(&oi), i=0;
            opt; opt=coap_option_next(&oi), i++)
        {
            opt_len = coap_opt_length(opt);
            opt_val = (const char*)coap_opt_value(opt);

            if (opt_len > 0 && opt_val) {
                str[str_len++] = '/';
                memcpy(&str[str_len], opt_val, opt_len);
                str_len += opt_len;
            }
        }

        if (str_len) {
            lua_pushlstring(L, str, str_len);
        } else {
            lua_pushnil(L);
        }
    }
    return 1;
}

/**
 * Set CoAP URI path.
 *
 * Lua arguments:
 *     uri_path [string|strings-array (1-based)]: URI path to set. The argument
 *         may specify the URI via string (e.g. "/a/b/c") or strings-array
 *         (e.g. {"a", "b", "c"})
 *
 * Lua return: None
 */
int l_coap_pdu_set_uri_path(lua_State *L)
{
    int arg_base;
    coap_pdu_t *pdu = ((ud_coap_pdu_t*)_get_self(L, &arg_base))->pdu;

    if (lua_type(L, arg_base+1) == LUA_TSTRING)
    {
        const char *uri = lua_tostring(L, arg_base+1);
        size_t i, len = luaL_len(L, arg_base+1);
        int b = -1, l;

        for (i = 0; i < len; i++)
        {
            if (b < 0 && uri[i] != '/') b = i;

            if (b >= 0) {
                if (uri[i] == '/') l = i - b;
                else if (i+1 >= len) l = len - b;
                else continue;

                if (!coap_add_option(
                    pdu, COAP_OPTION_URI_PATH, l, (const uint8_t*)&uri[b]))
                {
                    return luaL_error(L, "coap_add_option() failed; "
                        "check order of added options");
                }
                b = -1;
            }
        }
    } else
    if (lua_type(L, arg_base+1) == LUA_TTABLE)
    {
        size_t i, len = luaL_len(L, arg_base+1);

        for (i = 0; i < len; i++)
        {
            if (lua_rawgeti(L, arg_base+1, i+1) != LUA_TSTRING) {
                return luaL_error(L, "Invalid argument: strings-array expected");
            }

            if (!coap_add_option(pdu, COAP_OPTION_URI_PATH,
                luaL_len(L, -1), (const uint8_t*)lua_tostring(L, -1)))
            {
                return luaL_error(L, "coap_add_option() failed; "
                    "check order of added options");
            }
            lua_pop(L, 1);
        }
    } else {
        return luaL_error(L, "Invalid argument passed");
    }
    return 0;
}

/* free query string param iteration state */
static void _free_coap_qstr_param_iter_state(
    lua_State *L, coap_qstr_param_iter_state_t *iter_state)
{
    int i;

    for (i = 0; i < iter_state->n_refs; i++) {
        luaL_unref(L, LUA_REGISTRYINDEX, iter_state->refs[i]);
    }
    iter_state->n_refs = 0;
}

/*
 * Parse next CoAP Uri-Query option's content against parameter-value pair.
 * Returns 0 if last option has been parsed.
 */
static int _parse_next_coap_qstr_param(coap_opt_iterator_t *iter,
    const char **name, size_t *name_len, const char **val, size_t *val_len)
{
    coap_opt_t *opt;

    *name = *val = NULL;
    *name_len = *val_len = 0;

    opt = coap_option_next(iter);
    if (opt)
    {
        int qstr_len = coap_opt_length(opt);
        *name = (const char*)coap_opt_value(opt);

        /* look for '=' separating param name from its value */
        for (*name_len = 0; *name_len < qstr_len; (*name_len)++) {
            if ((*name)[*name_len] == '=') {
                *val = &(*name)[*name_len + 1];
                *val_len = qstr_len - *name_len - 1;
                break;
            }
        }

        /* trim leading and trailing spaces */
        if (*name_len) *name = strtrim(*name, name_len);
        if (*val_len) *val = strtrim(*val, val_len);
    } else
        return 0;

    return 1;
}

/* CoAP query string params iteration-function */
static int _coap_qstr_param_iter(lua_State *L)
{
    int i, found;
    const char *name, *val;
    size_t name_len, val_len;

    /* get passed iteration state and the control var */
    coap_qstr_param_iter_state_t *iter_state =
        (coap_qstr_param_iter_state_t*)lua_touserdata(L, 1);

    if (!iter_state)
        return luaL_argerror(L, 1, "Invalid iterator call");

next_iter:
    if (iter_state->iter.bad ||
        !_parse_next_coap_qstr_param(
            &iter_state->iter, &name, &name_len, &val, &val_len))
    {
        /* iteration finished */
        _free_coap_qstr_param_iter_state(L, iter_state);
        lua_pushnil(L);
        return 1;
    }

    if (!name_len) {
        /* ignore empty query strings */
        goto next_iter;
    }

    found = !iter_state->n_refs;

    /* filter to matching params only */
    for (i = 0; i < iter_state->n_refs && !found; i++)
    {
        const char *name_f; /* taken from filter */

        lua_pushinteger(L, iter_state->refs[i]);
        lua_gettable(L, LUA_REGISTRYINDEX);
        name_f = lua_tostring(L, -1);

        found = (luaL_len(L, -1) == name_len && !memcmp(name, name_f, name_len));

        lua_pop(L, 1);
    }

    if (!found) {
        /* param filtered out, go to the next one */
        goto next_iter;
    }

    /* 1st returned value: query string parameter name */
    lua_pushlstring(L, name, name_len);

    /* 2nd returned value: query string parameter value */
    if (val_len > 0)
        lua_pushlstring(L, val, val_len);
    else
        lua_pushnil(L);

    return 2;
}

/**
 * CoAP query string parameters iterator.
 *
 * NOTE: There is performance penalty when using this function with filtering
 *     arguments (see below). Therefore it's recommended to use 'get_qstr_param'
 *     to obtain single value for a specific parameter or iterate over all
 *     parameters via this iterator.
 *
 * Lua arguments:
 *     qstr_param(s) [string(s)|none]: 0 or more parameter names (up to 10)
 *         to obtain via iteration. If not provided all parameters are taken
 *         into account.
 *
 * Lua return:
 *     next [C function]: Query string parameters iteration-function.
 *     state [userdata]: Iteration state (coap_qstr_param_iter_state_t struct).
 *     cv_init [nil]: Init control variable value (not used).
 */
int l_coap_pdu_qstr_params(lua_State *L)
{
    int arg_base, i, n_args;
    coap_pdu_t *pdu = ((ud_coap_pdu_t*)_get_self(L, &arg_base))->pdu;

    coap_opt_filter_t filter;
    coap_option_filter_clear(filter);
    coap_option_filter_set(filter, COAP_OPTION_URI_QUERY);

    n_args = lua_gettop(L) - arg_base;
    if (n_args > MAX_QSTR_PARAMS_ARGS)
        return luaL_error(L,
            "Number of arguments exceeded %d", MAX_QSTR_PARAMS_ARGS);

    /* check arguments validity */
    for (i = 0; i < n_args; i++)
        luaL_checkstring(L, arg_base+i+1);

    /* query string params iteration-function */
    lua_pushcfunction(L, _coap_qstr_param_iter);

    /* iteration state */
    coap_qstr_param_iter_state_t *iter_state =
        lua_newuserdata(L, sizeof(coap_qstr_param_iter_state_t));
    memset(iter_state, 0, sizeof(coap_qstr_param_iter_state_t));

    for (i = 0; i < n_args; i++)
    {
        /* create copies of the passed arguments and save references to them */
        lua_pushvalue(L, arg_base+i+1);
        iter_state->refs[i] = luaL_ref(L, LUA_REGISTRYINDEX);
        iter_state->n_refs++;
    }

    coap_option_iterator_init(pdu, &iter_state->iter, filter);

    /* init control variable value (not used) */
    lua_pushnil(L);

    /* no closing value returned (4th parameter absent) */
    return 3;
}

/**
 * Get query string parameter.
 *
 * NOTE: In case a parameter has many values the first one is returned.
 *     To obtain all values of a given parameter the query string parameters
 *     iterator shall be used.
 *
 * Lua arguments:
 *     qstr_param [string]: Parameter name to obtain value for.
 *
 * Lua return:
 *     value [string]: Returns nil in case parameter value is empty or the
 *         parameter doesn't exists. Next returned value allows to distinguish
 *         between these cases.
 *     exist [bool]: true in case parameter exists, false otherwise.
 */
int l_coap_pdu_get_qstr_param(lua_State *L)
{
    int arg_base;
    const char *qstr_param;
    coap_opt_iterator_t oi;
    coap_pdu_t *pdu = ((ud_coap_pdu_t*)_get_self(L, &arg_base))->pdu;

    const char *name, *val;
    size_t name_len, val_len;

    coap_opt_filter_t filter;
    coap_option_filter_clear(filter);
    coap_option_filter_set(filter, COAP_OPTION_URI_QUERY);

    qstr_param = luaL_checkstring(L, arg_base+1);

    if (!coap_option_iterator_init(pdu, &oi, filter))
    {
        /* no options in PDU */
        lua_pushnil(L);
        lua_pushboolean(L, 0);
        return 2;
    }

next_iter:
    if (!_parse_next_coap_qstr_param(&oi, &name, &name_len, &val, &val_len))
    {
        /* param not found */
        lua_pushnil(L);
        lua_pushboolean(L, 0);
        return 2;
    }

    if (!name_len) {
        /* ignore empty query strings */
        goto next_iter;
    }

    if (!(luaL_len(L, arg_base+1) == name_len &&
        !memcmp(name, qstr_param, name_len)))
    {
        /* param filtered out, go to the next one */
        goto next_iter;
    }

    /* query string parameter value */
    if (val_len > 0) {
        lua_pushlstring(L, val, val_len);
    } else {
        lua_pushnil(L);
    }
    lua_pushboolean(L, 1);

    return 2;
}

/**
 * Get CoAP message payload.
 *
 * NOTE: For performance reason for string payload it's always better to use
 *     get_payload(false).
 *
 * Lua arguments:
 *     as_arr [bool|none]: If true return payload as bytes-array, false - as
 *         string (default if not provided).
 *
 * Lua return:
 *     payload [nil|string|bytes-array (1-based)] Payload.
 *         nil for an empty payload.
 */
int l_coap_pdu_get_payload(lua_State *L)
{
    int arg_base, as_arr = 0;
    size_t i, len = 0;
    uint8_t *data = NULL;
    coap_pdu_t *pdu = ((ud_coap_pdu_t*)_get_self(L, &arg_base))->pdu;

    if (lua_gettop(L) >= arg_base+1)
        as_arr = lua_toboolean(L, arg_base+1);

    coap_get_data(pdu, &len, &data);
    if (!len) {
        lua_pushnil(L);
        return 1;
    }

    if (as_arr) {
        lua_createtable(L, len, 0);
        for (i = 0; i < len; i++) {
            lua_pushinteger(L, data[i]);
            lua_rawseti(L, -2, i+1);
        }
    } else {
        lua_pushlstring(L, (const char*)data, len);
    }
    return 1;
}

/**
 * Get connection object associated with a given message. The object may be
 * later used to send CoAP request over the connection.
 *
 * NOTE: The routine is request/response handlers specific (when a message is
 *     associated with its connection).
 *
 * Lua arguments: None
 *
 * Lua return:
 *     conn [userdata] Connection object.
 */
int l_coap_pdu_get_connection(lua_State *L)
{
    ud_coap_pdu_t *ud_pdu = ((ud_coap_pdu_t*)_get_self(L, NULL));
    ud_connection_t *ud_conn =
        (ud_connection_t*)lua_newuserdata(L, sizeof(ud_connection_t));

    memset(ud_conn, 0, sizeof(ud_connection_t));
    ud_conn->session = ud_pdu->session;

    /* Connection object is assigned to already opened, external to
       the created object, client-server CoAP session. In this case
       the connection can't be automatically closed by its destructor
       (garbage collector's callback). */
    ud_conn->gc = 0;
    luaL_setmetatable(L, MT_CONNECTION);

    return 1;
}

/* set PDU payload from arg on the stack */
static void _set_payload(lua_State *L, coap_pdu_t *pdu, int arg)
{
    size_t i, len = 0;
    uint8_t *data = NULL;

    if (lua_type(L, arg) == LUA_TSTRING) {
        len = luaL_len(L, arg);
        data = (uint8_t*)lua_tostring(L, arg);
    } else
    if (lua_type(L, arg) == LUA_TTABLE)
    {
        len = luaL_len(L, arg);
        if (len > 0) {
            if (!(data = alloca(len)))
                luaL_error(L, "No memory");

            for (i = 0; i < len; i++) {
                if (lua_rawgeti(L, arg, i+1) != LUA_TNUMBER) {
                    luaL_error(L, "Invalid argument: bytes-array expected");
                }
                data[i] = (uint8_t)lua_tointeger(L, -1);
                lua_pop(L, 1);
            }
        }
    } else
    if (lua_gettop(L) >= arg)
        luaL_error(L, "Invalid argument passed");

    coap_add_data(pdu, len, data);
}

/**
 * Send CoAP message with a given payload.
 *
 * NOTE: The routine is request handler specific. The message being sent is
 *     always CoAP response for the handled request.
 * NOTE: After the routine is called the PDU object is locked and can not be
 *     accessed anymore.
 * NOTE: The routine doesn't actually send the message rather than sets its
 *     payload via coap_add_data() libcoap routine. The message will be sent
 *     automatically on request handler exit (_coap_req_hndlr() routine).
 * NOTE: Passing payload as bytes-array should be avoided due to its performance
 *     penalty.
 *
 * Lua arguments:
 *     code [int|none]: CoAP code. If not provided default code is set
 *         (according to the handled request). Note the CoAP type is also set
 *         automatically to ACK or NON according to the handled request. If
 *         there is a need to change this type, set_type() function shall be
 *         used before calling this routine.
 *     payload [string|bytes-array (1-based)|none]: Payload. Send empty payload
 *         if not provided.
 *
 * Lua return: None
 */
int l_coap_pdu_send_reqh(lua_State *L)
{
    int arg;
    ud_coap_pdu_t *ud_pdu = ((ud_coap_pdu_t*)_get_self(L, &arg));
    coap_pdu_t *pdu = ud_pdu->pdu;

    arg++;
    if (lua_type(L, arg) == LUA_TNUMBER) {
        int code = lua_tointeger(L, arg);
        pdu->code = COAP_RESPONSE_CODE(code);
        arg++;
    }

    if (!pdu->code) {
        pdu->code = COAP_RESPONSE_CODE(ud_pdu->def_code);
        log_info("CoAP code not provided for a message being sent; using %d\n",
            ud_pdu->def_code);
    }

    _set_payload(L, pdu, arg);

    /* lock for access */
    ud_pdu->access.lck = 1;

    return 0;
}

/**
 * Get connection's remote/local address.
 *
 * Lua arguments:
 *     local [bool|none]: If true return local interface address associated with
 *         the connection, false - remote address (default if not provided).
 *
 * Lua return:
 *     addr [string]: Requested address. nil in case of error (unlikely).
 */
int l_coap_conn_get_addr(lua_State *L)
{
    void *saddr;
    char addr_b[64];
    coap_address_t *caddr;
    int arg_base, local = 0, fa;

    coap_session_t *session =
        ((ud_connection_t*)_get_self(L, &arg_base))->session;

    if (lua_gettop(L) >= arg_base+1)
        local = lua_toboolean(L, arg_base+1);

    caddr = (local ? &session->addr_info.local : &session->addr_info.remote);
    fa = caddr->addr.sa.sa_family;

    saddr = (fa == AF_INET ?  (void*)&caddr->addr.sin.sin_addr :
        (fa == AF_INET6 ? (void*)&caddr->addr.sin6.sin6_addr : NULL));

    if (!inet_ntop(fa, saddr, addr_b, sizeof(addr_b)))
    {
        log_error("inet_ntop() failed: %s\n", strerror(errno));
        lua_pushnil(L);
    } else {
        lua_pushstring(L, addr_b);
    }
    return 1;
}

/**
 * Get connection's remote/local port.
 *
 * Lua arguments:
 *     local [bool|none]: If true return local interface port associated with
 *         the connection, false - remote port (default if not provided).
 *
 * Lua return:
 *     port [int]: Requested port number. 0 in case of error (unlikely).
 */
int l_coap_conn_get_port(lua_State *L)
{
    coap_address_t *caddr;
    int arg_base, local = 0, port = 0, fa;

    coap_session_t *session =
        ((ud_connection_t*)_get_self(L, &arg_base))->session;

    if (lua_gettop(L) >= arg_base+1)
        local = lua_toboolean(L, arg_base+1);

    caddr = (local ? &session->addr_info.local : &session->addr_info.remote);
    fa = caddr->addr.sa.sa_family;

    port = ntohs(fa == AF_INET ? caddr->addr.sin.sin_port :
        (fa == AF_INET6 ? caddr->addr.sin6.sin6_port : 0));

    lua_pushinteger(L, port);
    return 1;
}

/**
 * Get max PDU size for a connection respecting underlying MTU to avoid IP
 * fragmentation.
 *
 * Lua arguments: None
 *
 * Lua return:
 *    max_pdu [int] Max PDU size in bytes.
 */
int l_coap_conn_get_max_pdu_size(lua_State *L)
{
    coap_session_t *session = ((ud_connection_t*)_get_self(L, NULL))->session;
    lua_pushinteger(L, coap_session_max_pdu_size(session));
    return 1;
}

/**
 * Get max number of retransmits for not ACKed CON messages.
 *
 * Lua arguments: None
 *
 * Lua return:
 *     max_retransmit [int]: Max number of retransmits.
 */
int l_coap_conn_get_max_retransmit(lua_State *L)
{
    coap_session_t *session = ((ud_connection_t*)_get_self(L, NULL))->session;
    lua_pushinteger(L, session->max_retransmit);
    return 1;
}

/**
 * Set max number of retransmits for not ACKed CON messages.
 *
 * Lua arguments:
 *     max_retransmit [int]: Max number of retransmits (> 0).
 *
 * Lua return: None
 */
int l_coap_conn_set_max_retransmit(lua_State *L)
{
    int arg_base;
    coap_session_t *session =
        ((ud_connection_t*)_get_self(L, &arg_base))->session;

    unsigned max_retransmit = luaL_checkinteger(L, arg_base+1);
    assert(max_retransmit > 0);

    session->max_retransmit = max_retransmit;
    return 0;
}

/**
 * Get wait for ACK timeout.
 *
 * Lua arguments: None
 *
 * Lua return:
 *     timeout [int]: Wait for ACK timeout (ms).
 */
int l_coap_conn_get_ack_timeout(lua_State *L)
{
    coap_session_t *session = ((ud_connection_t*)_get_self(L, NULL))->session;
    lua_pushinteger(L, 1000 * session->ack_timeout.integer_part +
        session->ack_timeout.fractional_part);
    return 1;
}

/**
 * Set wait for ACK timeout.
 *
 * Lua arguments:
 *     timeout [int]: Wait for ACK timeout (ms; > 0).
 *
 * Lua return: None
 */
int l_coap_conn_set_ack_timeout(lua_State *L)
{
    int arg_base;
    coap_session_t *session =
        ((ud_connection_t*)_get_self(L, &arg_base))->session;

    coap_fixed_point_t timeout_fp;
    unsigned timeout = luaL_checkinteger(L, arg_base+1);
    assert(timeout > 0);

    timeout_fp.integer_part = timeout / 1000;
    timeout_fp.fractional_part = timeout % 1000;
    session->ack_timeout = timeout_fp;
    return 0;
}

/**
 * Send CoAP message over a connection.
 *
 * NOTE: Passing payload as bytes-array should be avoided due to its performance
 *     penalty.
 * NOTE: After calling this routine process_step() shall be used to finalize
 *     the sending process and wait for a response (if required). The PDU object
 *     is locked and can not be accessed anymore.
 *
 * Lua arguments:
 *     msg [userdata]: PDU object to send.
 *     payload [string|bytes-array (1-based)|none]: Payload. Send empty payload
 *         if not provided.
 *
 * Lua return: None
 */
int l_coap_conn_send(lua_State *L)
{
    int arg_base;
    coap_session_t *session =
        ((ud_connection_t*)_get_self(L, &arg_base))->session;
    ud_coap_pdu_t *ud_pdu =
        (ud_coap_pdu_t*)luaL_checkudata(L, arg_base+1, MT_PDU);
    coap_pdu_t *pdu = ud_pdu->pdu;

    if (ud_pdu->access.hndlr != ACS_NO_HNDLR) {
        return luaL_error(L,
            "Use this routine for messages created by new_msg()");
    }

    _set_payload(L, pdu, arg_base+2);
    _log_pdu(LOG_INF, "new", pdu, 0);

    if (coap_send(session, pdu) == COAP_INVALID_TID) {
        log_error("coap_send() failed\n");
    }

    /* lock for access */
    ud_pdu->access.lck = 1;

    return 0;
}

/**
 * Create a new CoAP message.
 *
 * Lua arguments:
 *     type [int]: CoAP message type.
 *     code [int]: CoAP message code.
 *     msg_id [int]: CoAP message id. Unambiguously identifies request-response
 *         transaction.
 *
 * Lua return:
 *     msg [userdata]: Newly created empty CoAP message. Use appropriate methods
 *         to fill the message with required content (token, options, payload).
 */
int l_coap_new_msg(lua_State *L)
{
    coap_pdu_t *pdu;
    ud_coap_pdu_t *ud_pdu;
    lib_ctx_t *lib_ctx = _get_lib_ctx(L);

    int type = luaL_checkinteger(L, 1);
    int code = luaL_checkinteger(L, 2);
    int msg_id = luaL_checkinteger(L, 3);

    pdu = coap_pdu_init(
        type, COAP_RESPONSE_CODE(code), msg_id, lib_ctx->cfg.max_pdu_sz);
    if (!pdu)
        luaL_error(L, "coap_pdu_init() failed");

    /* create new PDU object and associate it with its metatable */
    ud_pdu = (ud_coap_pdu_t*)lua_newuserdata(L, sizeof(ud_coap_pdu_t));
    memset(ud_pdu, 0, sizeof(ud_coap_pdu_t));
    ud_pdu->pdu = pdu;
    ud_pdu->access.hndlr = ACS_NO_HNDLR;
    luaL_setmetatable(L, MT_PDU);

    log_debug("New PDU object [%p] created\n", ud_pdu);

    return 1;
}

/*
 * Get libcaop address 'dst' fot given host address and port.
 * Returns NULL on error.
 */
static coap_address_t *_get_coap_addr(
    const char *host, int port, coap_address_t *dst)
{
    int err;
    char port_str[8] = {0};

    struct addrinfo *res = NULL, *ainfo;
    struct addrinfo hints;

    if (port < 0 || port > 65535)
        return NULL;

    sprintf(port_str, "%d", port);

    memset(dst, 0, sizeof(*dst));

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_DGRAM;

    err = getaddrinfo(host, port_str, &hints, &res);

    if (err != 0) {
        log_error("getaddrinfo() failed: %s\n", gai_strerror(err));
        return NULL;
    }

    for (ainfo = res; ainfo != NULL; ainfo = ainfo->ai_next)
    {
        switch (ainfo->ai_family)
        {
        case AF_INET6:
        case AF_INET:
            dst->size = ainfo->ai_addrlen;
            memcpy(&dst->addr.sa, ainfo->ai_addr, dst->size);
            goto loop_break;

        default:
            break;
        }
    }
loop_break:

    if (res) freeaddrinfo(res);
    return dst;
}

/*
 * Check argument arg on the stack against Lua function type OR global Lua
 * function name OR nil (default handler). Set reference to it in the registry
 * if not nil. Return 'def' if no argument is on the stack.
 */
static int _set_hndlr_ref(lua_State *L, int arg, int def)
{
    int ref = def, n_args = lua_gettop(L);

    if (n_args >= arg)
    {
        int type = lua_type(L, arg);

        if (type != LUA_TFUNCTION && type != LUA_TSTRING && type != LUA_TNIL) {
            return luaL_argerror(
                L, arg, "Expected function, string or nil");
        }

        if (type == LUA_TFUNCTION) {
            /* make sure Lua function is on top of the stack */
            lua_pushvalue(L, arg);

            /* make reference and pop the referenced function */
            ref = luaL_ref(L, LUA_REGISTRYINDEX);
        } else
        if (type == LUA_TSTRING) {
            const char *hndlr_name = lua_tostring(L, arg);

            if (lua_getglobal(L, hndlr_name) != LUA_TFUNCTION) {
                return luaL_error(L,
                    "%s is not a global function name", hndlr_name);
            }

            /* make reference and pop the referenced function */
            ref = luaL_ref(L, LUA_REGISTRYINDEX);
        } else {
            /* default handler */
            ref = LUA_NOREF;
        }
    }
    return ref;
}

/**
 * Bind the CoAP server for a given interface and port.
 *
 * Lua arguments:
 *     intf_addr [string]: Interface address the server is bind to e.g.
 *         "0.0.0.0" (IPv4), "::" (IPv6).
 *     port [int]: Port number the server is listening on.
 *     req_handler [Lua function|string|none]: Request handler (Lua function
 *         or function global name). If not provided don't change the handler
 *         (use default or the one already set by set_req_handler() method).
 *
 * Lua return: None
 */
int l_coap_bind_server(lua_State *L)
{
    lib_ctx_t *lib_ctx = _get_lib_ctx(L);
    coap_address_t bind_addr;

    const char *intf_addr = luaL_checkstring(L, 1);
    int reqh, port = luaL_checkinteger(L, 2);

    if (port < 0 || port >= 65535)
        return luaL_error(L, "Invalid port number %d", port);

    if (!_get_coap_addr(intf_addr, port, &bind_addr))
        return luaL_error(L, "Can't resolve address %s:%d", intf_addr, port);

    /* free previous endpoint if set */
    if (lib_ctx->coap.ep)
        coap_free_endpoint(lib_ctx->coap.ep);

    lib_ctx->coap.ep = coap_new_endpoint(
        lib_ctx->coap.ctx, &bind_addr, COAP_PROTO_UDP);

    if (!lib_ctx->coap.ep)
        return luaL_error(L, "coap_new_endpoint() failed");

    reqh = _set_hndlr_ref(L, 3, lib_ctx->ref.reqh);

    if (reqh != lib_ctx->ref.reqh) {
        /* unref previous handler if set */
        if (lib_ctx->ref.reqh != LUA_NOREF)
            luaL_unref(L, LUA_REGISTRYINDEX, lib_ctx->ref.reqh);

        lib_ctx->ref.reqh = reqh;
    }

    log_info("Server bound to %s:%d\n", intf_addr, port);

    return 0;
}

/**
 * Create new CoAP client connection for a given CoAP server address and port.
 *
 * Lua arguments:
 *     addr [string]: CoAP server address.
 *     port [int]: CoAP server port.
 *
 * Lua return:
 *     conn [userdata] Connection object.
 */
int l_coap_new_connection(lua_State *L)
{
    lib_ctx_t *lib_ctx = _get_lib_ctx(L);
    ud_connection_t *ud_conn;
    coap_address_t srv_addr;
    coap_session_t *session;

    const char *addr = luaL_checkstring(L, 1);
    int port = luaL_checkinteger(L, 2);

    if (port < 0 || port >= 65535)
        return luaL_error(L, "Invalid port number %d", port);

    if (!_get_coap_addr(addr, port, &srv_addr))
        return luaL_error(L, "Can't resolve address %s:%d", addr, port);

    session = coap_new_client_session(
        lib_ctx->coap.ctx, NULL, &srv_addr, COAP_PROTO_UDP);
    if (!session)
        return luaL_error(L, "coap_new_client_session() failed");

    ud_conn = (ud_connection_t*)lua_newuserdata(L, sizeof(ud_connection_t));
    memset(ud_conn, 0, sizeof(ud_connection_t));
    ud_conn->session = session; 

    /* Connection is automatically closed by its destructor (garbage
       collector's callback) on the end of object's lifetime. */
    ud_conn->gc = 1; 
    luaL_setmetatable(L, MT_CONNECTION);

    log_debug("New connection object [%p] created\n", ud_conn);

    return 1;
}

/**
 * CoAP messages processing loop. The routine must be called periodically in
 * a script main loop.
 *
 * Lua arguments:
 *     timeout [int]: Incomming message timeout (msec). If not provided - block
 *         until some message arrives.
 *
 * Lua return:
 *      time_spent [int]: Number of msecs spent in the routine. Negative value
 *          as an error indicator.
 */
int l_coap_process_step(lua_State *L)
{
    lib_ctx_t *lib_ctx = _get_lib_ctx(L);
    int time_spent;

    if (lua_gettop(L)) {
        int timeout = luaL_checkinteger(L, 1);

        time_spent = coap_run_once(
            lib_ctx->coap.ctx, timeout <= 0 ? COAP_RUN_NONBLOCK : timeout);
    } else {
        time_spent = coap_run_once(lib_ctx->coap.ctx, COAP_RUN_BLOCK);
    }

    if (time_spent < 0) {
        log_error("coap_run_once() failed\n");
    }
    lua_pushinteger(L, time_spent);
    return 1;
}

/**
 * Get libcoap log level.
 *
 * Lua arguments: None
 *
 * Lua return:
 *     log_level [int]: libcoap log level.
 */
int l_coap_get_libcoap_log_level(lua_State *L)
{
    lua_pushinteger(L, coap_get_log_level());
    return 1;
}

/**
 * Set libcoap log level (default: WARNING).
 *
 * Lua arguments:
 *     log_level [int]: libcoap log level.
 *
 * Lua return: None
 */
int l_coap_set_libcoap_log_level(lua_State *L)
{
    int log_level = luaL_checkinteger(L, 1);
    assert(log_level >= LOG_EMERG && log_level <= LOG_DEBUG);
    coap_set_log_level(log_level);
    return 0;
}

/**
 * Get CoAP request handler.
 *
 * Lua arguments: None
 *
 * Lua return:
 *     req_handler [Lua function|nil]: Handler function or nil (for default
 *         handler).
 */
int l_coap_get_req_handler(lua_State *L)
{
    lib_ctx_t *lib_ctx = _get_lib_ctx(L);

    if (lib_ctx->ref.reqh != LUA_NOREF) {
        lua_pushinteger(L, lib_ctx->ref.reqh);
        lua_gettable(L, LUA_REGISTRYINDEX);
    } else {
        lua_pushnil(L);
    }
    return 1;
}

/**
 * Set CoAP request handler.
 *
 * Lua arguments:
 *     req_handler [Lua function|string|nil|none]: Request handler (Lua function
 *         or function global name). If not provided or nil use default handler.
 *
 * Lua return: None
 */
int l_coap_set_req_handler(lua_State *L)
{
    lib_ctx_t *lib_ctx = _get_lib_ctx(L);
    int reqh = _set_hndlr_ref(L, 1, LUA_NOREF);

    if (reqh != lib_ctx->ref.reqh) {
        /* unref previous handler if set */
        if (lib_ctx->ref.reqh != LUA_NOREF)
            luaL_unref(L, LUA_REGISTRYINDEX, lib_ctx->ref.reqh);

        lib_ctx->ref.reqh = reqh;
    }
    return 0;
}

/**
 * Get CoAP response handler.
 *
 * Lua arguments: None
 *
 * Lua return:
 *     resp_handler [Lua function|nil]: Handler function or nil (for default
 *         handler).
 */
int l_coap_get_resp_handler(lua_State *L)
{
    lib_ctx_t *lib_ctx = _get_lib_ctx(L);

    if (lib_ctx->ref.resph != LUA_NOREF) {
        lua_pushinteger(L, lib_ctx->ref.resph);
        lua_gettable(L, LUA_REGISTRYINDEX);
    } else {
        lua_pushnil(L);
    }
    return 1;
}

/**
 * Set CoAP response handler.
 *
 * Lua arguments:
 *     resp_handler [Lua function|string|nil|none]: Response handler (Lua
 *         function or function global name). If not provided or nil use default
 *         handler.
 *
 * Lua return: None
 */
int l_coap_set_resp_handler(lua_State *L)
{
    lib_ctx_t *lib_ctx = _get_lib_ctx(L);
    int resph = _set_hndlr_ref(L, 1, LUA_NOREF);

    if (resph != lib_ctx->ref.resph) {
        /* unref previous handler if set */
        if (lib_ctx->ref.resph != LUA_NOREF)
            luaL_unref(L, LUA_REGISTRYINDEX, lib_ctx->ref.resph);

        lib_ctx->ref.resph = resph;
    }
    return 0;
}

/**
 * Get CoAP NACK handler.
 *
 * Lua arguments: None
 *
 * Lua return:
 *     nack_handler [Lua function|nil]: Handler function or nil (for default
 *         handler).
 */
int l_coap_get_nack_handler(lua_State *L)
{
    lib_ctx_t *lib_ctx = _get_lib_ctx(L);

    if (lib_ctx->ref.nackh != LUA_NOREF) {
        lua_pushinteger(L, lib_ctx->ref.nackh);
        lua_gettable(L, LUA_REGISTRYINDEX);
    } else {
        lua_pushnil(L);
    }
    return 1;
}

/**
 * Set CoAP NACK handler.
 *
 * Lua arguments:
 *     resp_handler [Lua function|string|nil|none]: Response handler (Lua
 *         function or function global name). If not provided or nil use default
 *         handler.
 *
 * Lua return: None
 */
int l_coap_set_nack_handler(lua_State *L)
{
    lib_ctx_t *lib_ctx = _get_lib_ctx(L);
    int nackh = _set_hndlr_ref(L, 1, LUA_NOREF);

    if (nackh != lib_ctx->ref.nackh) {
        /* unref previous handler if set */
        if (lib_ctx->ref.nackh != LUA_NOREF)
            luaL_unref(L, LUA_REGISTRYINDEX, lib_ctx->ref.nackh);

        lib_ctx->ref.nackh = nackh;
    }
    return 0;
}

/**
 * Set max PDU size for newly created messeges.
 *
 * Lua arguments:
 *     max_pdu_sz [int]: Max PDU size. If not configured default value is used
 *         as specified by MAX_COAP_PDU_SIZE.
 *
 * Lua return: None
 */
int l_coap_set_max_pdu_size(lua_State *L)
{
    lib_ctx_t *lib_ctx = _get_lib_ctx(L);
    lib_ctx->cfg.max_pdu_sz = luaL_checkinteger(L, 1);
    return 0;
}

/* get default CoAP response code */
static int _get_coap_resp_code(int req_code)
{
    switch (req_code)
    {
    case COAP_REQUEST_GET:
        return 205; /* Content */
        break;
    case COAP_REQUEST_POST:
        return 204; /* Changed */
        break;
    case COAP_REQUEST_PUT:
        return 201; /* Created */
        break;
    case COAP_REQUEST_DELETE:
        return 202; /* Deleted */
        break;
    case COAP_REQUEST_FETCH:
        return 205; /* Content */
        break;
    case COAP_REQUEST_PATCH:
        return 204; /* Changed */
        break;
    case COAP_REQUEST_IPATCH:
        return 204; /* Changed */
        break;
    }

    /* Empty */
    return 0;
}

/* global (all-resource) CoAP request handler */
static void _coap_req_hndlr(
    coap_context_t *context, struct coap_resource_t *resource,
    coap_session_t *session, coap_pdu_t *request, coap_binary_t *token,
    coap_string_t *query_str, coap_pdu_t *response)
{
    ud_coap_pdu_t *ud_req, *ud_resp;
    lua_State *L = coap_get_app_data(context);
    lib_ctx_t *lib_ctx = _get_lib_ctx(L);

    _log_pdu(LOG_INF, "reqh", request, 1);

    if (lib_ctx->ref.reqh != LUA_NOREF) {
        lua_pushinteger(L, lib_ctx->ref.reqh);
        lua_gettable(L, LUA_REGISTRYINDEX);
    } else
    /* if no handler is set try use default one */
    if (lua_getglobal(L, REQ_HANDLER) != LUA_TFUNCTION)
    {
        lua_pop(L, 1);
        return;
    }

    /* create handler arguments; associate them with their metatables */

    ud_req = (ud_coap_pdu_t*)lua_newuserdata(L, sizeof(ud_coap_pdu_t));
    memset(ud_req, 0, sizeof(ud_coap_pdu_t));
    ud_req->pdu = request;
    ud_req->session = session;
    ud_req->access.ro = 1;    /* request is read only */
    ud_req->access.hndlr = ACS_REQ_HNDLR;
    luaL_setmetatable(L, MT_PDU);

    ud_resp = (ud_coap_pdu_t*)lua_newuserdata(L, sizeof(ud_coap_pdu_t));
    memset(ud_resp, 0, sizeof(ud_coap_pdu_t));
    ud_resp->pdu = response;
    ud_resp->session = session;
    ud_resp->def_code = _get_coap_resp_code(request->code);
    ud_resp->access.hndlr = ACS_REQ_HNDLR;
    luaL_setmetatable(L, MT_PDU);

    lua_call(L, 2, 0);

    /* response with non-empty code will be sent
       automatically after leaving this handler */
    if (response->code) {
        _log_pdu(LOG_INF, "reqh", response, 0);
    }
}

/* global CoAP response handler */
void _coap_resp_hndlr(
    struct coap_context_t *context, coap_session_t *session,
    coap_pdu_t *sent, coap_pdu_t *received, const coap_tid_t id)
{
    ud_coap_pdu_t *ud_sent, *ud_rcvd;
    lua_State *L = coap_get_app_data(context);
    lib_ctx_t *lib_ctx = _get_lib_ctx(L);
    int ret_type, handle_ack = 1;

    _log_pdu(LOG_INF, "resph", received, 1);

    if (lib_ctx->ref.resph != LUA_NOREF) {
        lua_pushinteger(L, lib_ctx->ref.resph);
        lua_gettable(L, LUA_REGISTRYINDEX);
    } else
    /* if no handler is set try use default one */
    if (lua_getglobal(L, RESP_HANDLER) != LUA_TFUNCTION)
    {
        lua_pop(L, 1);
        goto finish;
    }

    /* create handler arguments; associate them with their metatables */

    ud_sent = (ud_coap_pdu_t*)lua_newuserdata(L, sizeof(ud_coap_pdu_t));
    memset(ud_sent, 0, sizeof(ud_coap_pdu_t));
    ud_sent->pdu = sent;
    ud_sent->session = session;
    ud_sent->access.ro = 1;
    ud_sent->access.hndlr = ACS_RESP_HNDLR;
    luaL_setmetatable(L, MT_PDU);

    ud_rcvd = (ud_coap_pdu_t*)lua_newuserdata(L, sizeof(ud_coap_pdu_t));
    memset(ud_rcvd, 0, sizeof(ud_coap_pdu_t));
    ud_rcvd->pdu = received;
    ud_rcvd->session = session;
    ud_rcvd->access.ro = 1;
    ud_rcvd->access.hndlr = ACS_RESP_HNDLR;
    luaL_setmetatable(L, MT_PDU);

    lua_call(L, 2, 1);

    /* check returned argument (if provided) */
    ret_type = lua_type(L, -1);
    if (ret_type == LUA_TBOOLEAN) {
        handle_ack = (lua_toboolean(L, -1) != 0);
    } else
    if (ret_type != LUA_TNIL) {
        log_warn("Ignoring invalid type [id: %d] returned by the CoAP response "
            "handler; boolean or nothing expected\n", ret_type);
    }
    lua_pop(L, 1);

finish:
    /* send ACK if required by the handled response */
    if (handle_ack && received->type == COAP_MESSAGE_CON)
    {
        coap_pdu_t *ack = coap_pdu_init(COAP_MESSAGE_ACK, 0, received->tid, 0);
        if (ack) {
            _log_pdu(LOG_INF, "resph", ack, 0);
        }
        if (!ack || coap_send(session, ack) == COAP_INVALID_TID) {
            log_error("coap_send() failed\n");
        }
    }
}

/* global CoAP NACK handler */
void _coap_nack_hndlr(struct coap_context_t *context, coap_session_t *session,
    coap_pdu_t *sent, coap_nack_reason_t reason, const coap_tid_t id)
{
    ud_coap_pdu_t *ud_sent;
    lua_State *L = coap_get_app_data(context);
    lib_ctx_t *lib_ctx = _get_lib_ctx(L);

    if (lib_ctx->ref.nackh != LUA_NOREF) {
        lua_pushinteger(L, lib_ctx->ref.nackh);
        lua_gettable(L, LUA_REGISTRYINDEX);
    } else
    /* if no handler is set try use default one */
    if (lua_getglobal(L, NACK_HANDLER) != LUA_TFUNCTION)
    {
        lua_pop(L, 1);
        return;
    }

    /* create handler arguments; associate them with their metatables */

    ud_sent = (ud_coap_pdu_t*)lua_newuserdata(L, sizeof(ud_coap_pdu_t));
    memset(ud_sent, 0, sizeof(ud_coap_pdu_t));
    ud_sent->pdu = sent;
    ud_sent->session = session;
    ud_sent->access.ro = 1;
    ud_sent->access.hndlr = ACS_NACK_HNDLR;
    luaL_setmetatable(L, MT_PDU);

    lua_pushinteger(L, reason);

    lua_pushinteger(L, id);

    lua_call(L, 3, 0);
}

/* search for a function name in 'funcs' table */
static lua_CFunction _get_func(const char *fname, const luaL_Reg *funcs)
{
    const char *n;
    for (; (n = funcs->name) != NULL; funcs++) {
        if (!strcmp(n, fname))
            return funcs->func;
    }
    return NULL;
}

#define __DECL_VARS() \
    const char *tname = (const char*)lua_touserdata(L, lua_upvalueindex(1)); \
    void *ud = luaL_checkudata(L, 1, tname); \
    const char *fname = luaL_checkstring(L, 2); \
    lua_CFunction f = NULL

/* push method on the stack along with its associated object as an upvalue */
#define __CHECK_FUNC_PUSH() \
    if (f) { \
        lua_pushlightuserdata(L, ud); \
        lua_pushcclosure(L, f, 1); \
    } else { \
        luaL_error(L, "Invalid method %s of object %s", fname, tname); \
    }

/* CoAP PDU object methods dispatcher */
static int _pdu_obj_dispacher(lua_State *L)
{
    /* base read access methods */
    static const luaL_Reg r_funcs[] = {
        {"get_type", l_coap_pdu_get_type},
        {"get_code", l_coap_pdu_get_code},
        {"get_msg_id", l_coap_pdu_get_msg_id},
        {"get_token", l_coap_pdu_get_token},
        {"options", l_coap_pdu_options},
        {"get_option", l_coap_pdu_get_option},
        {"get_uri_path", l_coap_pdu_get_uri_path},
        {"qstr_params", l_coap_pdu_qstr_params},
        {"get_qstr_param", l_coap_pdu_get_qstr_param},
        {"get_payload", l_coap_pdu_get_payload},
        {NULL, NULL}
    };

    /* base write access methods */
    static const luaL_Reg w_funcs[] = {
        {"set_type", l_coap_pdu_set_type},
        {"set_code", l_coap_pdu_set_code},
        {"set_msg_id", l_coap_pdu_set_msg_id},
        {"set_token", l_coap_pdu_set_token},
        {"set_option", l_coap_pdu_set_option},
        {"set_uri_path", l_coap_pdu_set_uri_path},
        {NULL, NULL}
    };

    /* all handlers (common) read access methods */
    static const luaL_Reg r_cmnh_funcs[] = {
        {"get_connection", l_coap_pdu_get_connection},
        {NULL, NULL}
    };

    /* request handler write access specfic methods */
    static const luaL_Reg w_reqh_funcs[] = {
        {"send", l_coap_pdu_send_reqh},
        {NULL, NULL}
    };

    /* response/NACK handler has no write access specific methods */
    static const luaL_Reg null_funcs[] = {
        {NULL, NULL}
    };

    __DECL_VARS();
    ud_coap_pdu_t *ud_pdu = (ud_coap_pdu_t*)ud;

    do {
        if (ud_pdu->access.lck) {
            return luaL_error(L,
                "Object is locked and can not be accessed anymore");
        }

        /* read access
         */

        /* base read access methods are common for all types of objects */
        if ((f = _get_func(fname, r_funcs)) != NULL) break;

        switch (ud_pdu->access.hndlr)
        {
        case ACS_REQ_HNDLR:
        case ACS_RESP_HNDLR:
        case ACS_NACK_HNDLR:
            f = _get_func(fname, r_cmnh_funcs);
            break;
        }
        if (f != NULL) break;

        /* write access
         */
        if (ud_pdu->access.ro) break;

        if ((f = _get_func(fname, w_funcs)) != NULL) break;

        switch (ud_pdu->access.hndlr)
        {
        case ACS_REQ_HNDLR:
            f = _get_func(fname, w_reqh_funcs);
            break;
        case ACS_RESP_HNDLR:
        case ACS_NACK_HNDLR:
            f = _get_func(fname, null_funcs);
            break;
        }
        if (f != NULL) break;
    }
    while (0);

    __CHECK_FUNC_PUSH();
    return 1;
}

/* CoAP PDU object destructor */
static int _pdu_obj_gc(lua_State *L)
{
    ud_coap_pdu_t *ud_pdu = (ud_coap_pdu_t*)lua_touserdata(L, 1);

    /* delete the PDU only in case it was created by new_msg() and has not
       been sent (sent messages are freed automatically by the library) */
    if (ud_pdu->access.hndlr == ACS_NO_HNDLR && !ud_pdu->access.lck) {
        coap_delete_pdu(ud_pdu->pdu);
        log_debug("Unsent PDU object [%p] freed\n", ud_pdu);
    }
    return 0;
}

/* connection object methods dispatcher */
static int _conn_obj_dispacher(lua_State *L)
{
    static const luaL_Reg funcs[] = {
        {"get_addr", l_coap_conn_get_addr},
        {"get_port", l_coap_conn_get_port},
        {"get_max_pdu_size", l_coap_conn_get_max_pdu_size},
        {"get_max_retransmit", l_coap_conn_get_max_retransmit},
        {"set_max_retransmit", l_coap_conn_set_max_retransmit},
        {"get_ack_timeout", l_coap_conn_get_ack_timeout},
        {"set_ack_timeout", l_coap_conn_set_ack_timeout},
        {"send", l_coap_conn_send},
        {NULL, NULL}
    };

    __DECL_VARS();

    f = _get_func(fname, funcs);
    __CHECK_FUNC_PUSH();

    return 1;
}

/* connection object destructor */
static int _conn_obj_gc(lua_State *L)
{
    ud_connection_t *ud_conn = (ud_connection_t*)lua_touserdata(L, 1);

    /* close the connection only in case it's eligible */
    if (ud_conn->gc) {
        coap_session_release(ud_conn->session);
        log_debug("Connection object [%p] freed\n", ud_conn);
    }
    return 0;
}

#undef __CHECK_FUNC_PUSH
#undef __DECL_VARS

/*
 * Create and initialize object's metatable:
 * 1. Set methods dispatcher as metatable indexing metamethod
 * 2. Set destructor method.
 */
static void _set_obj_metatable(lua_State *L, const char *tname,
    lua_CFunction obj_dispatcher, lua_CFunction obj_gc)
{
    if (luaL_newmetatable(L, tname)) {
        /*
         * metatable.__index = obj_dispatcher
         * metatable.__gc = obj_gc
         *
         * NOTE: Dispatcher upvalue set to the metatable name as light-userdata.
         */
        lua_pushstring(L, "__index");
        lua_pushlightuserdata(L, (void*)tname);
        lua_pushcclosure(L, obj_dispatcher, 1);
        lua_settable(L, -3);

        lua_pushstring(L, "__gc");
        lua_pushcfunction(L, obj_gc);
        lua_settable(L, -3);
    }
    lua_pop(L, 1);
}

/* initialize library context */
static void _init_lib_ctx(lib_ctx_t *lib_ctx, lua_State *L)
{
    memset(lib_ctx, 0, sizeof(lib_ctx_t));
    lib_ctx->cfg.max_pdu_sz = MAX_COAP_PDU_SIZE;
    lib_ctx->ref.reqh = LUA_NOREF;
    lib_ctx->ref.resph = LUA_NOREF;
    lib_ctx->ref.nackh = LUA_NOREF;

    if (!(lib_ctx->coap.ctx = coap_new_context(NULL))) {
        luaL_error(L, "coap_new_context() failed");
    }

    /* CoAP context is associated with its Lua state */
    coap_set_app_data(lib_ctx->coap.ctx, L);

    coap_register_nack_handler(lib_ctx->coap.ctx, _coap_nack_hndlr);

    /* register main request/response libcoap handlers */
    coap_register_response_handler(lib_ctx->coap.ctx, _coap_resp_hndlr);

    if (!(lib_ctx->coap.rsrc = coap_resource_unknown_init(_coap_req_hndlr))) {
        luaL_error(L, "coap_resource_unknown_init() failed");
    }

    coap_register_handler(lib_ctx->coap.rsrc, COAP_REQUEST_POST, _coap_req_hndlr);
    coap_register_handler(lib_ctx->coap.rsrc, COAP_REQUEST_GET, _coap_req_hndlr);
    coap_register_handler(lib_ctx->coap.rsrc, COAP_REQUEST_DELETE, _coap_req_hndlr);
    coap_register_handler(lib_ctx->coap.rsrc, COAP_REQUEST_FETCH, _coap_req_hndlr);
    coap_register_handler(lib_ctx->coap.rsrc, COAP_REQUEST_PATCH, _coap_req_hndlr);
    coap_register_handler(lib_ctx->coap.rsrc, COAP_REQUEST_IPATCH, _coap_req_hndlr);
    coap_add_resource(lib_ctx->coap.ctx, lib_ctx->coap.rsrc);
}

/* free library context */
static int _free_lib_ctx(lua_State *L)
{
    lib_ctx_t *lib_ctx = (lib_ctx_t*)lua_touserdata(L, 1);

    if (lib_ctx->ref.reqh != LUA_NOREF) {
        luaL_unref(L, LUA_REGISTRYINDEX, lib_ctx->ref.reqh);
        lib_ctx->ref.reqh = LUA_NOREF;
    }

    if (lib_ctx->ref.resph != LUA_NOREF) {
        luaL_unref(L, LUA_REGISTRYINDEX, lib_ctx->ref.resph);
        lib_ctx->ref.resph = LUA_NOREF;
    }

    if (lib_ctx->ref.nackh != LUA_NOREF) {
        luaL_unref(L, LUA_REGISTRYINDEX, lib_ctx->ref.nackh);
        lib_ctx->ref.nackh = LUA_NOREF;
    }

    if (lib_ctx->coap.ep) {
        coap_free_endpoint(lib_ctx->coap.ep);
        lib_ctx->coap.ep = NULL;
    }

    if (lib_ctx->coap.rsrc) {
        coap_delete_resource(lib_ctx->coap.ctx, lib_ctx->coap.rsrc);
        lib_ctx->coap.rsrc = NULL;
    }

    if (lib_ctx->coap.ctx) {
        coap_free_context(lib_ctx->coap.ctx);
        lib_ctx->coap.ctx = NULL;
    }

    log_debug(MOD_NAME_STR " library context freed for Lua state %p\n", L);

    /*
     * NOTE: coap_cleanup() is not called since other Lua states may still
     * be in use. libcoap resources will be freed at the process termination.
     */
    return 0;
}

/* contains initialization script as 'init_code' definition */
#define MOD_INIT_SCRIPT_HDR_STR XSTR(MOD_INIT_SCRIPT_HDR)
#include MOD_INIT_SCRIPT_HDR_STR

/**
 * Initialize library.
 */
int MOD_INIT_NAME(lua_State *L)
{
    static const luaL_Reg lib_funcs[] = {
        {"bind_server", l_coap_bind_server},
        {"new_connection", l_coap_new_connection},
        {"new_msg", l_coap_new_msg},
        {"process_step", l_coap_process_step},
        {"get_libcoap_log_level", l_coap_get_libcoap_log_level},
        {"set_libcoap_log_level", l_coap_set_libcoap_log_level},
        {"get_req_handler", l_coap_get_req_handler},
        {"set_req_handler", l_coap_set_req_handler},
        {"get_resp_handler", l_coap_get_resp_handler},
        {"set_resp_handler", l_coap_set_resp_handler},
        {"get_nack_handler", l_coap_get_nack_handler},
        {"set_nack_handler", l_coap_set_nack_handler},
        {"set_max_pdu_size", l_coap_set_max_pdu_size},
        {NULL, NULL}
    };

    /* init libcoap (reinit safe) */
    coap_startup();

    /* set objects metatables */
    _set_obj_metatable(L, MT_PDU, _pdu_obj_dispacher, _pdu_obj_gc);
    _set_obj_metatable(L, MT_CONNECTION, _conn_obj_dispacher, _conn_obj_gc);

    /* create the library context (as a userdata with its metatable) */
    if (luaL_newmetatable(L, MT_CONTEXT))
    {
        lib_ctx_t *lib_ctx = (lib_ctx_t*)lua_newuserdata(L, sizeof(lib_ctx_t));
        _init_lib_ctx(lib_ctx, L);

        /* swap userdata with metatable pushed on the stack */
        lua_insert(L, -2);

        /* set destructor for the library context */
        lua_pushstring(L, "__gc");
        lua_pushcfunction(L, _free_lib_ctx);
        lua_settable(L, -3);

        /* associate metatable with the userdata (pops the metatable) */
        lua_setmetatable(L, -2);

        /* add library context pointer to registry */
        lua_pushstring(L, MT_CONTEXT);
        lua_pushlightuserdata(L, lib_ctx);
        lua_settable(L, LUA_REGISTRYINDEX);

        /* create a reference to the library context userdata extending
           its lifetime up to the Lua state lifetime (pops the userdata) */
        luaL_ref(L, LUA_REGISTRYINDEX);
    } else {
        lua_pop(L, 1);
    }

    /* call the library initial code */
    if (luaL_loadbuffer(
        L, init_code, strlen(init_code), MOD_NAME_STR " init code") != LUA_OK)
    {
        return luaL_error(L, "Can't run "MOD_NAME_STR " init code");
    }
    lua_call(L, 0, 0);

    /* register library public interface */
    luaL_newlib(L, lib_funcs);

    log_debug(MOD_NAME_STR " library context initialized for Lua state %p\n", L);

    /* library registration struct on the stack */
    return 1;
}
