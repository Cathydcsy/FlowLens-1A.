-- FlowLens Companion for Wireshark. Lua 5.2+ / Wireshark 3.6+.
-- SPDX-License-Identifier: MIT
-- Standalone tap: no dissector, capture, network access, or FlowLens dependency.
local prior = rawget(_G, "__flowlens_companion_v1")
if prior then return prior end

local M = { version = "1.0.0" }
local field_names = {
    stream = "tcp.stream", src_port = "tcp.srcport", dst_port = "tcp.dstport",
    syn = "tcp.flags.syn", fin = "tcp.flags.fin", rst = "tcp.flags.reset",
    retransmission = "tcp.analysis.retransmission",
    fast_retransmission = "tcp.analysis.fast_retransmission",
    spurious_retransmission = "tcp.analysis.spurious_retransmission",
    duplicate_ack = "tcp.analysis.duplicate_ack",
    out_of_order = "tcp.analysis.out_of_order", zero_window = "tcp.analysis.zero_window",
    http_requests = "http.request", dns_response = "dns.flags.response"
}
local extractors, unavailable = {}, {}
for key, name in pairs(field_names) do
    local ok, extractor = pcall(Field.new, name)
    if ok then extractors[key] = extractor else unavailable[key] = name end
end

local function values(key)
    local extractor = extractors[key]
    if not extractor then return {} end
    -- Consume FieldInfo here; never retain it after the packet callback.
    local ok, fields = pcall(function() return { extractor() } end)
    if not ok then unavailable[key] = field_names[key]; return {} end
    local result = {}
    for _, field in ipairs(fields) do
        local good, value = pcall(function() return field.value end)
        if not good or value == nil then value = tostring(field) end
        result[#result + 1] = value
    end
    return result
end
local function truth(value)
    if value == true then return true end
    if value == false or value == nil then return false end
    local number = tonumber(value)
    if number then return number ~= 0 end
    return tostring(value):lower() == "true"
end
local function true_count(key)
    local count = 0
    for _, value in ipairs(values(key)) do if truth(value) then count = count + 1 end end
    return count
end
local function present(key) return #values(key) > 0 end
local function available(key) return extractors[key] ~= nil and unavailable[key] == nil end
local function endpoint(address, port)
    address = tostring(address or "?")
    if address:find(":", 1, true) then address = "[" .. address .. "]" end
    return address .. ":" .. tostring(port or "?")
end
local function pvalue(pinfo, key)
    local ok, value = pcall(function() return pinfo[key] end)
    if ok then return value end
end
local counter_names = { "syn", "fin", "rst", "retransmissions", "duplicate_ack",
    "out_of_order", "zero_window", "http_requests", "dns_queries" }
local weights = { retransmissions = 4, duplicate_ack = 2, rst = 3,
    zero_window = 4, out_of_order = 1 }
local function new_state()
    return { flows = {}, packets = 0, bytes = 0, skipped = 0, last_frame = nil }
end

function M.ingest(state, pinfo)
    local streams = values("stream")
    -- Multiple TCP layers cannot safely share the other field extractors.
    if #streams ~= 1 then state.skipped = state.skipped + 1; return end
    local id = tonumber(streams[1])
    if not id then state.skipped = state.skipped + 1; return end
    local frame = tonumber(pvalue(pinfo, "number"))
    -- The frame tap runs once per frame. Also tolerate duplicate callbacks and
    -- complete rescans without a reset, with O(streams), not O(packets), storage.
    if frame and state.last_frame and frame < state.last_frame then
        state.flows, state.packets, state.bytes, state.skipped = {}, 0, 0, 0
        state.last_frame = nil
    end
    if frame and frame == state.last_frame then return end
    state.last_frame = frame
    local row = state.flows[id]
    if not row then
        local a = endpoint(pvalue(pinfo, "src"), values("src_port")[1])
        local b = endpoint(pvalue(pinfo, "dst"), values("dst_port")[1])
        if b < a then a, b = b, a end
        row = { stream = id, endpoint_a = a, endpoint_b = b, packets = 0, bytes = 0 }
        for _, key in ipairs(counter_names) do row[key] = 0 end
        state.flows[id] = row
    end
    local length = tonumber(pvalue(pinfo, "len")) or 0
    local time = tonumber(tostring(pvalue(pinfo, "rel_ts") or ""))
    row.packets, row.bytes = row.packets + 1, row.bytes + length
    state.packets, state.bytes = state.packets + 1, state.bytes + length
    if time then
        row.start_s = math.min(row.start_s or time, time)
        row.end_s = math.max(row.end_s or time, time)
    end
    for _, key in ipairs({ "syn", "fin", "rst" }) do
        if true_count(key) > 0 then row[key] = row[key] + 1 end
    end
    if present("retransmission") or present("fast_retransmission")
            or present("spurious_retransmission") then
        row.retransmissions = row.retransmissions + 1
    end
    for _, key in ipairs({ "duplicate_ack", "out_of_order", "zero_window" }) do
        if present(key) then row[key] = row[key] + 1 end
    end
    row.http_requests = row.http_requests + true_count("http_requests")
    -- Count query messages, not questions: one message may have many questions.
    for _, response in ipairs(values("dns_response")) do
        if response == false or tonumber(response) == 0
                or tostring(response):lower() == "false" then
            row.dns_queries = row.dns_queries + 1
        end
    end
end

local function analysis_disabled()
    if type(get_preference) ~= "function" then return false end
    local ok, value = pcall(get_preference, "tcp.analyze_sequence_numbers")
    return ok and value == false
end
local function metric_available(key)
    if key == "dns_queries" then return available("dns_response") end
    if key == "retransmissions" then
        return not analysis_disabled() and available("retransmission")
            and available("fast_retransmission") and available("spurious_retransmission")
    end
    if key == "duplicate_ack" or key == "out_of_order" or key == "zero_window" then
        return not analysis_disabled() and available(key)
    end
    return available(key)
end
function M.snapshot(state)
    local rows = {}
    for _, source in pairs(state.flows) do
        local row = {}
        for key, value in pairs(source) do row[key] = value end
        for _, key in ipairs(counter_names) do
            if not metric_available(key) then row[key] = nil end
        end
        row.score, row.score_partial = 0, false
        for key, weight in pairs(weights) do
            if row[key] == nil then row.score_partial = true
            else row.score = row.score + row[key] * weight end
        end
        row.risk = row.score >= 12 and "HIGH" or (row.score >= 4 and "WATCH" or "LOW")
        if row.score_partial then
            row.risk = row.score < 4 and "UNKNOWN" or row.risk .. " (partial)"
        end
        rows[#rows + 1] = row
    end
    table.sort(rows, function(a, b)
        if a.score ~= b.score then return a.score > b.score end
        return a.stream < b.stream
    end)
    return rows
end
local function shown(value) return value == nil and "N/A" or tostring(value) end
local function seconds(value) return value and string.format("%.9f", value) or "N/A" end
function M.summary(state)
    local rows = M.snapshot(state)
    local lines = {
        "FlowLens Companion for Wireshark " .. M.version,
        string.format("TCP streams: %d | packets: %d | wire bytes: %d | skipped frames: %d",
            #rows, state.packets, state.bytes, state.skipped),
        "Scope: all TCP frames in the current capture (independent of display filter).",
        "Priority = 4*Retx + 2*DupACK + 3*RST + 4*ZeroWin + OOO; HIGH >= 12, WATCH >= 4.",
        "Priority indicates transport anomalies, not proof of an attack. N/A = unavailable.",
        "HTTP/DNS depend on Wireshark dissection/reassembly; DNS here is TCP only.",
        "Apply stream... enters an ID; pure Lua TextWindow has no row double-click API.", ""
    }
    local missing = {}
    for _, name in pairs(unavailable) do missing[#missing + 1] = name end
    table.sort(missing)
    if #missing > 0 then lines[#lines + 1] = "Unavailable fields: " .. table.concat(missing, ", ") end
    if analysis_disabled() then lines[#lines + 1] = "TCP sequence analysis is disabled: analysis counts are N/A." end
    if #rows == 0 then lines[#lines + 1] = "No aggregatable TCP streams. Open a capture and click Refresh." end
    for _, row in ipairs(rows) do
        lines[#lines + 1] = string.format("[%s] stream %d | score %d%s | %s <-> %s",
            row.risk, row.stream, row.score, row.score_partial and "+" or "", row.endpoint_a, row.endpoint_b)
        lines[#lines + 1] = string.format("  Packets %d | Bytes %d | SYN %s | FIN %s | RST %s",
            row.packets, row.bytes, shown(row.syn), shown(row.fin), shown(row.rst))
        lines[#lines + 1] = string.format("  Retx %s | DupACK %s | OOO %s | ZeroWin %s | HTTP %s | DNS(TCP) %s",
            shown(row.retransmissions), shown(row.duplicate_ack), shown(row.out_of_order),
            shown(row.zero_window), shown(row.http_requests), shown(row.dns_queries))
        lines[#lines + 1] = "  Start " .. seconds(row.start_s) .. " s | End " .. seconds(row.end_s) .. " s (capture-relative)"
        lines[#lines + 1] = ""
    end
    return table.concat(lines, "\n") .. "\n"
end
local csv_columns = { "stream", "risk", "score", "score_partial", "endpoint_a", "endpoint_b",
    "packets", "bytes", "syn", "fin", "rst", "retransmissions", "duplicate_ack", "out_of_order",
    "zero_window", "http_requests", "dns_queries", "start_s", "end_s" }
local function csv_cell(value)
    local text = shown(value)
    if text:find('[,"\r\n]') then text = '"' .. text:gsub('"', '""') .. '"' end
    return text
end
function M.csv(state)
    local lines = { table.concat(csv_columns, ",") }
    for _, row in ipairs(M.snapshot(state)) do
        local cells = {}
        for _, key in ipairs(csv_columns) do
            local value = row[key]
            if key == "start_s" or key == "end_s" then value = seconds(value) end
            cells[#cells + 1] = csv_cell(value)
        end
        lines[#lines + 1] = table.concat(cells, ",")
    end
    return table.concat(lines, "\r\n") .. "\r\n"
end
function M.export(state, path)
    if type(path) ~= "string" or path == "" or path:find("%z") then return nil, "Invalid CSV path." end
    local old = io.open(path, "rb")
    if old then old:close(); return nil, "Destination already exists; choose a new filename." end
    local file, err = io.open(path, "wb")
    if not file then return nil, tostring(err) end
    local ok, write_err = file:write(M.csv(state))
    local closed, close_err = file:close()
    if not ok or not closed then return nil, tostring(write_err or close_err) end
    return true
end
function M.apply_stream(state, input)
    if not gui_enabled() then return nil, "Display filters require the Wireshark GUI." end
    local text = tostring(input or ""):match("^%s*(%d+)%s*$")
    local id = text and tonumber(text)
    if not id or not state.flows[id] then return nil, "Enter a stream ID present in this summary." end
    local filter = "tcp.stream == " .. string.format("%.0f", id)
    local ok, err = pcall(function() set_filter(filter); apply_filter() end)
    if not ok then return nil, tostring(err) end
    return filter
end
function M.listen(on_draw)
    local state = new_state()
    local tap = Listener.new(nil, "tcp", true) -- Three arguments also work in 3.6.
    tap.packet = function(pinfo) M.ingest(state, pinfo) end
    tap.reset = function()
        local fresh = new_state()
        for key in pairs(state) do state[key] = nil end
        for key, value in pairs(fresh) do state[key] = value end
    end
    tap.draw = function() on_draw(state) end
    return state, tap
end
local gui_windows = {}
function M.open_window()
    local window = TextWindow.new("FlowLens Companion - TCP 会话汇总")
    local status = "Choose Export CSV... to save a new file. No automatic export."
    local closed, state, tap = false, nil, nil
    local function render()
        if not closed and state then window:set(M.summary(state) .. "\n" .. status .. "\n") end
    end
    local ok, err = pcall(function() state, tap = M.listen(render) end)
    if not ok then window:set("Cannot register TCP listener: " .. tostring(err)); return end
    gui_windows[window] = tap
    local function retap()
        local good, problem = pcall(retap_packets)
        if not good then status = "Refresh unavailable: " .. tostring(problem) end
        render()
    end
    window:set_atclose(function()
        closed = true
        gui_windows[window] = nil
        pcall(function() tap:remove() end)
    end)
    window:add_button("Refresh", retap)
    window:add_button("Apply stream...", function()
        new_dialog("FlowLens - Apply stream filter", function(id)
            if closed then return end
            local filter, problem = M.apply_stream(state, id)
            status = filter and ("Applied display filter: " .. filter) or ("Filter failed: " .. problem)
            render()
        end, "Stream ID (see summary)")
    end)
    window:add_button("Filter top stream", function()
        local rows = M.snapshot(state)
        local filter, problem = M.apply_stream(state, rows[1] and rows[1].stream)
        status = filter and ("Applied display filter: " .. filter) or ("Filter failed: " .. problem)
        render()
    end)
    window:add_button("Export CSV...", function()
        local default = persconffile_path("flowlens-" .. os.date("%Y%m%d-%H%M%S") .. ".csv")
        status = "CSV default path (blank input): " .. default
        render()
        new_dialog("FlowLens - Export CSV (new file)", function(path)
            if closed then return end
            if not path or path:match("^%s*$") then path = default end
            local good, problem = M.export(state, path)
            status = good and ("CSV exported: " .. path) or ("CSV export failed: " .. problem)
            render()
        end, "CSV path (blank = path shown in summary)")
    end)
    render()
    retap()
end
set_plugin_info({ version = M.version, author = "FlowLens contributors",
    description = "Independent TCP session summary, anomaly priority, display filters and CSV" })
if gui_enabled() then register_menu("FlowLens/TCP 会话汇总", M.open_window, MENU_TOOLS_UNSORTED) end
register_stat_cmd_arg("flowlens", function(argument)
    local path
    if argument ~= "flowlens" then
        path = argument:match("^flowlens,csv=(.+)$")
        if not path then error("Usage: -z flowlens OR -z flowlens,csv=<new CSV path>") end
    end
    M.listen(function(state)
        print(M.summary(state))
        if path then
            local ok, err = M.export(state, path)
            if ok then print("FlowLens CSV exported: " .. path)
            else io.stderr:write("FlowLens CSV export failed: " .. err .. "\n") end
        end
    end)
end)
M.new_state = new_state
M.field_names = field_names
rawset(_G, "__flowlens_companion_v1", M)
return M
