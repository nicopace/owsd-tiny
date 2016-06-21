
These are proof of concept clients which call ubus over websocket to device
given on command line. There are two clients:

- wifiimport client, which connects to device, listens for ubus event
  'wireless.credentials', and executes 'sbin/wifi import $@' with the
  arguments. Intended as proof of concept that syncs up wifi settings.

- blinkwps client, which connects to device, makes ubus calls to log in, then
  repeatedly every 5 seconds blinks on off the WPS led by doing ubus calls
  'led.wps set' and 'led.wps status'.
