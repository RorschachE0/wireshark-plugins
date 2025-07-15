-- TCP Flow Diagram Wireshark Plugin
-- Displays per-stream TCP packet flows in a simple text sequence diagram.

if not gui_enabled() then
    return
end

local tcp_stream_f   = Field.new("tcp.stream")
local ip_src_f       = Field.new("ip.src")
local ip_dst_f       = Field.new("ip.dst")
local tcp_srcport_f  = Field.new("tcp.srcport")
local tcp_dstport_f  = Field.new("tcp.dstport")
-- We'll parse the combined flags bitfield manually. This avoids issues
-- with missing per-flag fields on some versions of Wireshark.
local tcp_flags_f    = Field.new("tcp.flags")

local streams = {}

local band
if bit32 then
    band = bit32.band
elseif bit then
    band = bit.band
else
    -- Lua 5.3+ supports bit operators directly
    band = function(a, b) return a & b end
end

local function format_flags()
    local f = tcp_flags_f()
    if not f then
        return "-"
    end
    local val = f.value
    local flags = ""
    if band(val, 0x02) ~= 0 then flags = flags .. "S" end
    if band(val, 0x10) ~= 0 then flags = flags .. "A" end
    if band(val, 0x01) ~= 0 then flags = flags .. "F" end
    if band(val, 0x04) ~= 0 then flags = flags .. "R" end
    if band(val, 0x08) ~= 0 then flags = flags .. "P" end
    if flags == "" then flags = "-" end
    return flags
end

local function packet_listener()
    local tap = Listener.new("tcp")

    function tap.packet(pinfo, tvb)
        local stream_field = tcp_stream_f()
        if not stream_field then return end
        local stream = tostring(stream_field)
        local entry = {
            time  = string.format("%.6f", pinfo.rel_ts),
            src   = tostring(ip_src_f()),
            dst   = tostring(ip_dst_f()),
            sport = tostring(tcp_srcport_f()),
            dport = tostring(tcp_dstport_f()),
            len   = pinfo.len,
            flags = format_flags()
        }
        if not streams[stream] then streams[stream] = {} end
        table.insert(streams[stream], entry)
    end

    local win = TextWindow.new("TCP Flow Diagram")

    local function draw()
        win:clear()
        for stream, items in pairs(streams) do
            win:append(string.format("Stream %s\n", stream))
            win:append(string.format("%-23s %-23s\n", "Source", "Destination"))
            for _, e in ipairs(items) do
                local left = string.format("%s:%s", e.src, e.sport)
                local right = string.format("%s:%s", e.dst, e.dport)
                win:append(string.format("%8s %-23s --> %-23s len %-5d [%s]\n",
                    e.time, left, right, e.len, e.flags))
            end
            win:append("\n")
        end
    end

    win:set_atclose(function() tap:remove() end)
    win:add_button("Refresh", draw)

    function tap.draw()
        draw()
    end

    function tap.reset()
        streams = {}
        win:clear()
    end

    draw()
end

register_menu("TCP Flow Diagram", packet_listener, MENU_TOOLS_UNSORTED)
