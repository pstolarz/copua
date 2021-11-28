--
-- Copyright (c) 2021 Piotr Stolarz
-- Copua: Lua CoAP library
--
-- Sample CoAP client
--

local coap = require("copua")

local done = false

--
-- CoAP response handler
--
local function resp_handler(req_sent, resp_rcvd)
    local conn = resp_rcvd.get_connection()
    print(string.format(
        "Response received from: %s:%d", conn.get_addr(), conn.get_port()));

    print("CoAP response details:")
    print(string.format(" Type: %s", CoapTypeName[resp_rcvd.get_type()]))
    print(string.format(" Code: %s", CoapCodeName[resp_rcvd.get_code()]))
    print(string.format(" MsgId: %s", resp_rcvd.get_msg_id()))

    print(" Options:")
    for opt, val in resp_rcvd.options() do
        print(string.format("  %s: %s", CoapOptionName[opt], val))
    end

    local payload = resp_rcvd.get_payload()
    if (payload) then
        print(" Payload:")
        print(string.format("  %s", payload))
    end

    done = true

    -- send ACK if required
    return true
end

local function main()
    coap.set_resp_handler(resp_handler)
    local conn = coap.new_connection("coap.me", 5683)

    local msg = coap.new_msg(CoapType.CON, CoapCode.GET, math.random(0, 0xffff));
    msg.set_uri_path("/hello")
    conn.send(msg)
    repeat
        coap.process_step()
    until done
end

main()
