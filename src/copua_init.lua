--
-- Copyright (c) 2021 Piotr Stolarz
-- Copua: Lua CoAP library
--
-- Library initialization script. It contains various library constants
-- definitions in a form of indexed tables (aka enums).
--
-- NOTE: The script is embedded into library code and executed during its
-- loading phase.
--

local function _make_rev(tab)
    inv_tab = {};
    for k,v in pairs(tab) do
        inv_tab[v] = k
    end
    return inv_tab
end

--
-- CoAP message types
--
CoapType = {
    CON = 0,
    NON = 1,
    ACK = 2,
    RST = 3
}
CoapTypeName = _make_rev(CoapType)

--
-- CoAP message codes
--
CoapCode = {
    -- Method: 1.XX
    EMPTY = 0,
    GET = 1,
    POST = 2,
    PUT = 3,
    DELETE = 4,
    FETCH = 5,
    PATCH = 6,
    IPATCH = 7,

    -- Success: 2.XX
    CREATED = 201,
    DELETED = 202,
    VALID = 203,
    CHANGED = 204,
    CONTENT = 205,
    CONTINUE = 231,

    -- Client Errors: 3.XX
    BAD_REQUEST = 400,
    UNAUTHORIZED = 401,
    BAD_OPTION = 402,
    FORBIDDEN = 403,
    NOT_FOUND = 404,
    METHOD_NOT_ALLOWED = 405,
    NOT_ACCEPTABLE = 406,
    REQUEST_ENTITY_INCOMPLETE = 408,
    CONFLICT = 409,
    PRECONDITION_FAILED = 412,
    REQUEST_ENTITY_TOO_LARGE = 413,
    UNSUPPORTED_CONTENT_FORMAT = 415,
    UNPROCESSABLE_ENTITY = 422,
    TOO_MANY_REQUESTS = 429,

    -- Server Errors: 5.XX
    INTERNAL_SERVER_ERROR = 500,
    NOT_IMPLEMENTED = 501,
    BAD_GATEWAY = 502,
    SERVICE_UNAVAILABLE = 503,
    GATEWAY_TIMEOUT = 504,
    PROXYING_NOT_SUPPORTED = 505,
    HOP_LIMIT_REACHED = 508,

    -- Signaling codes: 7.XX
    CSM = 701,
    PING = 702,
    PONG = 703,
    RELEASE = 704,
    ABORT = 705
}
CoapCodeName = _make_rev(CoapCode)

--
-- CoAP option types
--
CoapOption = {
    IF_MATCH = 1,
    URI_HOST = 3,
    ETAG = 4,
    IF_NONE_MATCH = 5,
    OBSERVE = 6,
    URI_PORT = 7,
    LOCATION_PATH = 8,
    URI_PATH = 11,
    CONTENT_FORMAT = 12,
    MAXAGE = 14,
    URI_QUERY = 15,
    ACCEPT = 17,
    LOCATION_QUERY = 20,
    BLOCK2 = 23,
    BLOCK1 = 27,
    SIZE2 = 28,
    PROXY_URI = 35,
    PROXY_SCHEME = 39,
    SIZE1 = 60,
    NORESPONSE = 258
}
CoapOptionName = _make_rev(CoapOption)

--
-- CoAP format types
--
CoapFormat = {
    TEXT_PLAIN = 0,
    APPLICATION_COSE_ENCRYPT0 = 16,
    APPLICATION_COSE_MAC0 = 17,
    APPLICATION_COSE_SIGN1 = 18,
    APPLICATION_LINK_FORMAT = 40,
    APPLICATION_XML = 41,
    APPLICATION_OCTET_STREAM = 42,
    APPLICATION_RDF_XML = 43,
    APPLICATION_EXI = 47,
    APPLICATION_JSON = 50,
    APPLICATION_CBOR = 60,
    APPLICATION_COSE_ENCRYPT = 96,
    APPLICATION_COSE_MAC = 97,
    APPLICATION_COSE_SIGN = 98,
    APPLICATION_COSE_KEY = 101,
    APPLICATION_COSE_KEY_SET = 102,
    APPLICATION_SENML_JSON = 110,
    APPLICATION_SENSML_JSON = 111,
    APPLICATION_SENML_CBOR = 112,
    APPLICATION_SENSML_CBOR = 113,
    APPLICATION_SENML_EXI = 114,
    APPLICATION_SENSML_EXI = 115,
    APPLICATION_SENML_XML = 310,
    APPLICATION_SENSML_XML = 311
}
CoapFormatName = _make_rev(CoapFormat)

--
-- libcoap log levels
--
LibCoapLogLevel = {
  LIBCOAP_LOG_EMERG = 0,
  LIBCOAP_LOG_ALERT = 1,
  LIBCOAP_LOG_CRIT = 2,
  LIBCOAP_LOG_ERR = 3,
  LIBCOAP_LOG_WARNING = 4,
  LIBCOAP_LOG_NOTICE = 5,
  LIBCOAP_LOG_INFO = 6,
  LIBCOAP_LOG_DEBUG = 7
}
LibCoapLogLevelName = _make_rev(LibCoapLogLevel)

--
-- NACK handler reason code
--
NackReasonCode = {
    NACK_TOO_MANY_RETRIES = 0,
    NACK_NOT_DELIVERABLE = 1,
    NACK_RST = 2,
    NACK_TLS_FAILED = 3,
    NACK_ICMP_ISSUE = 4
}
NackReasonCodeName = _make_rev(NackReasonCode)
