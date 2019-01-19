# OWSD web socket daemon

This is a fork of http://public.inteno.se/owsd.git without SSL, ubus-proxy and dbus support. 
OpenWrt build files that do a static link against libwebsockets are in `openwrt`. 

The final .ipkg is only 53kb and has no dependencies 

Usage: 

`feeds.conf`: 

    src-git owsd https://gitlab.bau-ha.us/mt/owsd-tiny
    
`.config`: 

    CONFIG_PACKAGE_owsd=y 
    

## Overview
- uses web sockets to accept RPC calls in JSON-RPC
- intended as web back-end for ~~Inteno JUCI Web UI on OpenWrt based platform~~ experiments :) 
- RPCs are routed to local IPC bus objects on ubus
- supports receiving events in addition to issuing method calls
- uses ubus session object to perform access control
- JSON-RPC format is compatible with [uhttpd-mod-ubus](https://wiki.openwrt.org/doc/techref/ubus#access_to_ubus_over_http)
- basic HTTP file serving logic is available
- powered by libwebsockets, libubox, libubus

## Supported RPCs
- "list"
  * lists available object and methods; identical to [uhttpd-mod-ubus](https://wiki.openwrt.org/doc/techref/ubus#access_to_ubus_over_http)
- "call"
  * call method of an object; identical to [uhttpd-mod-ubus](https://wiki.openwrt.org/doc/techref/ubus#access_to_ubus_over_http)
- "subscribe"
  * start listening for broadcast events by glob (wildcard) pattern
- "subscribe-list"
  * list which events we are listening for
- "unsubscribe"
  * stop listening

## ubus support
- methods on ubus objects can be called via the "call" rpc
- events sent via ubus\_send\_event can be received
- ACL checks are made prior to calling methods on ubus objects - the ubus session object is accessed to verify if session ID field has access
- ACL checks are also made prior to notifying clients of events they are listening for - "owsd" is used as the scope to check for "read" permission on the event

## ubus proxy support - networked ubus
- using ubus proxy support, ubus objects can be proxied over the network across two hosts
- with two hosts, _client_ with ubus proxy support connects to remote _server_, and lists available objects
- remotely available objects are created on the local _client_'s ubus, calling methods of these (_stub_) objects results in RPC calls to the _server_'s objects
- see this [screencast](https://asciinema.org/a/3u1dl3ojggxih31wi495dr4zj)


## Manual test run

If you run the owsd as RPC server to listen on some port (e.g. 1234)

`owsd -p 1234`

then it is easiest to test/connect with a tool like `wscat`:

`wscat -c 'ws://127.0.0.1' -s ubus-json`

The established web socket can be used to send RPCs in the JSON format.

## Tests

In the test/ subdirectory, there is a very simple test runner made in nodejs. It is configured by editing parameters `config.js`, and running:

`node client.js [session-id]`

The `config.js` file specifies the text file containing test input and expected output. See existing text files for examples of RPC commands.

## Other resources: libwebsockets documentation

https://libwebsockets.org/lws-api-doc-master/html/md_README.coding.html
