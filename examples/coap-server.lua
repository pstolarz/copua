--
-- Copyright (c) 2021 Piotr Stolarz
-- Copua: Lua CoAP library
--
-- Sample CoAP server
--

local coap = require("copua")

--
-- CoAP request handler
--
local function req_handler(req, resp)
    local conn = req.get_connection()
    print(string.format("Remote peer: %s:%d", conn.get_addr(), conn.get_port()));

    print("CoAP request details:")
    print(string.format(" Type: %s", CoapTypeName[req.get_type()]))
    print(string.format(" Code: %s", CoapCodeName[req.get_code()]))
    print(string.format(" MsgId: %s", req.get_msg_id()))

    local token = req.get_token(true)
    if (token) then
        print(string.format(" Token: %s", bytes2hex(token)))
    end

    local uri_path = req.get_uri_path()
    if (uri_path) then
        print(string.format(" Uri-Path: %s", uri_path))
    end

    print(" Query parameters:")
    for prm, val in req.qstr_params() do
        print(string.format("  %s: %s", prm, val))
    end

    print(" Options:")
    for opt, val in req.options() do
        print(string.format("  %s: %s", CoapOptionName[opt], val))
    end

    local payload = req.get_payload()
    if (payload) then
        print(" Payload:")
        print(string.format("  %s", payload))
    end

    if (req.get_type() == CoapType.CON) then
        resp.set_option(CoapOption.CONTENT_FORMAT, CoapFormat.APPLICATION_JSON)
        resp.send("{}")
    end
end

local function main()
    coap.bind_server("0.0.0.0", 5683, req_handler)

    repeat
        coap.process_step()
    until false;
end

main()
