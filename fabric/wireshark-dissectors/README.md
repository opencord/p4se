Wireshark Dissector for the Switch to CPU Protocol
==================================================

For testing, start with:
```
wireshark -X lua_script:cpu_header.lua
```

To enable the dissector for every start of wireshark,
copy `init.lua` into the wireshark config:
 ```
~/.config/wireshark on Ubuntu
 ```
and copy `cpu_header.lua` into the wireshark Lua folder:
```
~/.config/wireshark/lua
```
