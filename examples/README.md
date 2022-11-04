# Examples

Run an example by:
```
./run.sh SCRIPT
```

### [`CoAP Client`](coap-client.lua)

Sample CoAP client. Connects to [coap.me](https://coap.me) and sends `GET`
request for `/hello` resource.

### [`CoAP Server`](coap-server.lua)

Sample CoAP server. Waits for incomming requests and dumps a request details
on the standard output.

To test the server use `coap-client` (part of `libcoap2-bin` package):
```
coap-client -m get 'coap://127.0.0.1/hello?prm1=1&prm2=2'
```
