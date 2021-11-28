# Copua = CoAP + Lua

Copua is a CoAP library for Lua. It's implemented as a thin wrapper around
[libcoap](https://libcoap.net) C library.

## Build

OpenSSL development library is needed to compile this library:
```
sudo apt-get install libssl-dev
```

Then initialize a building environment (needed to be called only once):
```
make init
```

and build by:
```
make
```

## Examples

See enclosed [examples](examples) for a quick start.

## Library API

As listed in the following tables each Lua method is implemented by its own
C function in [`copua.c`](src/copua.c). The in-line doc for the C functions
documents the corresponding Lua methods.

### Library Methods

| Lua method              | C method (implementation)      |
|-------------------------|--------------------------------|
| `bind_server`           | `l_coap_bind_server`           |
| `new_connection`        | `l_coap_new_connection`        |
| `new_msg`               | `l_coap_new_msg`               |
| `process_step`          | `l_coap_process_step`          |
| `get_libcoap_log_level` | `l_coap_get_libcoap_log_level` |
| `set_libcoap_log_level` | `l_coap_set_libcoap_log_level` |
| `get_req_handler`       | `l_coap_get_req_handler`       |
| `set_req_handler`       | `l_coap_set_req_handler`       |
| `get_resp_handler`      | `l_coap_get_resp_handler`      |
| `set_resp_handler`      | `l_coap_set_resp_handler`      |
| `get_nack_handler`      | `l_coap_get_nack_handler`      |
| `set_nack_handler`      | `l_coap_set_nack_handler`      |
| `set_max_pdu_size`      | `l_coap_set_max_pdu_size`      |

### CoAP PDU Object Methods

| Lua method         | C method (implementation)   | Notes |
|--------------------|-----------------------------|-------|
| `get_type`         | `l_coap_pdu_get_type`       |       |
| `set_type`         | `l_coap_pdu_set_type`       |       |
| `get_code`         | `l_coap_pdu_get_code`       |       |
| `set_code`         | `l_coap_pdu_set_code`       |       |
| `get_msg_id`       | `l_coap_pdu_get_msg_id`     |       |
| `set_msg_id`       | `l_coap_pdu_set_msg_id`     |       |
| `get_token`        | `l_coap_pdu_get_token`      |       |
| `set_token`        | `l_coap_pdu_set_token`      |       |
| `options`          | `l_coap_pdu_options`        |       |
| `get_option`       | `l_coap_pdu_get_option`     |       |
| `set_option`       | `l_coap_pdu_set_option`     |       |
| `get_uri_path`     | `l_coap_pdu_get_uri_path`   |       |
| `set_uri_path`     | `l_coap_pdu_set_uri_path`   |       |
| `qstr_params`      | `l_coap_pdu_qstr_params`    |       |
| `get_qstr_param`   | `l_coap_pdu_get_qstr_param` |       |
| `get_payload`      | `l_coap_pdu_get_payload`    |       |
| `get_connection`   | `l_coap_pdu_get_connection` | Available from request/response handlers only |
| `send`             | `l_coap_pdu_send_reqh`      | Available from request handler only |

### Connection Object Methods

| Lua method           | C method (implementation)        | Notes |
|----------------------|----------------------------------|-------|
| `get_addr`           | `l_coap_conn_addr`               |       |
| `get_port`           | `l_coap_conn_port`               |       |
| `get_max_pdu_size`   | `l_coap_conn_get_max_pdu_size`   |       |
| `get_max_retransmit` | `l_coap_conn_get_max_retransmit` |       |
| `set_max_retransmit` | `l_coap_conn_set_max_retransmit` |       |
| `get_ack_timeout`    | `l_coap_conn_get_ack_timeout`    |       |
| `set_ack_timeout`    | `l_coap_conn_set_ack_timeout`    |       |
| `send`               | `l_coap_conn_send`               | For PDUs created by `new_msg` only |

## License

2 clause BSD license. See [`LICENSE`](LICENSE) file for details.
