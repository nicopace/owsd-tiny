
These are proof of concept clients which call ubus over websocket to device
given on command line. There are two clients:

- wifiimport client, which connects to device, listens for ubus event
  'wireless.credentials', and executes 'sbin/wifi import $@' with the
  arguments. Intended as proof of concept that syncs up wifi settings.

- blinkwps client, which connects to device, makes ubus calls to log in, then
  repeatedly every 5 seconds blinks on off the WPS led by doing ubus calls
  'led.wps set' and 'led.wps status'.


The test PoC clients can be build for OpenWrt device even without creating a package:

----
export STAGING_DIR=/opt/inteno/iopsys/staging_dir/target-mips_mips32_uClibc-0.9.33.2/

$STAGING_DIR/../host/bin/cmake -DCMAKE_FIND_ROOT_PATH=$STAGING_DIR \
	-DCMAKE_C_COMPILER=$STAGING_DIR/../toolchain-mips_mips32_gcc-4.8-linaro_uClibc-0.9.33.2/bin/mips-openwrt-linux-gcc \
	..

make
----
