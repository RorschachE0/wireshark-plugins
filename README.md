# wireshark-plugins

A collection of simple Wireshark Lua plugins. Copy the `.lua` files to your
Wireshark plugins directory and restart Wireshark to load them.

## tcp_flow_diagram.lua

Visualizes TCP conversations as a basic text sequence diagram.

1. Start capturing packets in Wireshark.
2. Choose **Tools → TCP Flow Diagram** to open the window.
3. Click **Refresh** to retap packets and update the display.
4. Each stream shows packet direction, length and TCP flags for quick
   inspection.