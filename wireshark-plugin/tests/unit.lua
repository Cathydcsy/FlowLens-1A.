-- 隔离的 API 模拟，只能通过 tests/test_plugin.py 运行，不要安装这个文件。
local path = assert(os.getenv("FLOWLENS_TEST_SOURCE"), "Run with test_plugin.py")
local file = assert(io.open(path, "rb"))
local source = file:read("*a"); file:close()
local unpack_values = table.unpack or unpack
local passed = 0
local function check(label, action)
    action()
    passed = passed + 1
    print("PASS " .. label)
end

local function instance(missing, headless)
    local context = { fields = {}, taps = {}, buttons = {}, menus = 0, sequence = true, filters = 0 }
    local env = setmetatable({}, { __index = _G })
    env._G = env
    env.__flowlens_companion_v1 = false
    env.Field = { new = function(name)
        if missing and missing[name] then error("Field unavailable: " .. name) end
        return function()
            local result = {}
            for _, value in ipairs(context.fields[name] or {}) do result[#result + 1] = { value = value } end
            return unpack_values(result)
        end
    end }
    env.gui_enabled = function() return not headless end
    env.set_plugin_info = function(info) assert(info.version == "1.0.0") end
    env.register_menu = function(name, callback)
        assert(name == "FlowLens/TCP 会话汇总")
        context.menus = context.menus + 1; context.menu = callback
    end
    env.register_stat_cmd_arg = function(name, callback) context.stat = callback end
    env.Listener = { new = function(tap, filter, allfields, fourth)
        assert(tap == nil and filter == "tcp" and allfields and fourth == nil)
        local listener = { remove = function() context.removed = true end }
        context.taps[#context.taps + 1] = listener
        return listener
    end }
    env.get_preference = function(name)
        assert(name == "tcp.analyze_sequence_numbers"); return context.sequence
    end
    env.set_filter = function(filter) context.filter = filter end
    env.apply_filter = function() context.filters = context.filters + 1 end
    env.new_dialog = function(title, callback) context.dialog = callback end
    env.persconffile_path = function(name) return name end
    env.retap_packets = function()
        for _, tap in ipairs(context.taps) do tap.reset(); tap.draw() end
    end
    env.TextWindow = { new = function()
        local window = {}
        function window:set(text) context.text = text; return self end
        function window:set_atclose(callback) context.close = callback end
        function window:add_button(label, callback) context.buttons[label] = callback end
        return window
    end }
    local loader = assert(load(source, "@flowlens_companion.lua", "t", env))
    return loader(), context, env, loader
end

local function feed(module, context, state, id, number, changes)
    context.fields = {
        ["tcp.stream"] = { id }, ["tcp.srcport"] = { 1234 }, ["tcp.dstport"] = { 80 },
        ["tcp.flags.syn"] = { false }, ["tcp.flags.fin"] = { false }, ["tcp.flags.reset"] = { false }
    }
    for key, value in pairs(changes or {}) do context.fields[key] = value end
    module.ingest(state, { number = number, src = "2001:db8::1", dst = "2001:db8::2",
        len = 100, rel_ts = number / 10 })
end

local module, context, env, loader = instance()
local state = module.new_state()
check("false flags stay zero; IPv6 endpoints; relative times", function()
    feed(module, context, state, 10, 1)
    local row = module.snapshot(state)[1]
    assert(row.syn == 0 and row.fin == 0 and row.rst == 0)
    assert(row.endpoint_a == "[2001:db8::1]:1234" and row.end_s == 0.1)
end)
check("union of retransmission classes counts once; HTTP and DNS messages", function()
    feed(module, context, state, 10, 2, {
        ["tcp.analysis.retransmission"] = { true },
        ["tcp.analysis.fast_retransmission"] = { true },
        ["tcp.analysis.spurious_retransmission"] = { true },
        ["tcp.analysis.duplicate_ack"] = { true }, ["tcp.analysis.zero_window"] = { true },
        ["tcp.analysis.out_of_order"] = { true }, ["tcp.flags.reset"] = { true },
        ["http.request"] = { true, true, false }, ["dns.flags.response"] = { false, false, true }
    })
    local row = module.snapshot(state)[1]
    assert(row.retransmissions == 1 and row.score == 14 and row.risk == "HIGH")
    assert(row.http_requests == 2 and row.dns_queries == 2)
end)
check("duplicate callback does not inflate counts", function()
    feed(module, context, state, 10, 2)
    assert(state.packets == 2 and state.bytes == 200)
end)
check("score ordering and stable stream-ID ties", function()
    feed(module, context, state, 7, 3)
    feed(module, context, state, 5, 4)
    local rows = module.snapshot(state)
    assert(rows[1].stream == 10 and rows[2].stream == 5 and rows[3].stream == 7)
end)
check("CSV escapes commas, double quotes and newlines", function()
    state.flows[5].endpoint_a = 'host,"quoted"\n:5'
    assert(module.csv(state):find('"host,""quoted""\n:5"', 1, true))
    assert(module.csv(state):sub(-2) == "\r\n")
end)
check("filter input validation prevents arbitrary expressions", function()
    for _, input in ipairs({ "-1", "1.5", "10 or ip", "999", "", "nan" }) do
        assert(not module.apply_stream(state, input))
    end
    assert(context.filters == 0)
    assert(module.apply_stream(state, " 010 ") == "tcp.stream == 10" and context.filters == 1)
end)
check("missing optional field gives N/A and partial/unknown score", function()
    local m, c = instance({ ["tcp.analysis.zero_window"] = true, ["http.request"] = true })
    local s = m.new_state(); feed(m, c, s, 0, 1)
    local row = m.snapshot(s)[1]
    assert(row.zero_window == nil and row.http_requests == nil and row.risk == "UNKNOWN")
    assert(row.score_partial and m.summary(s):find("Unavailable fields", 1, true))
    assert(m.csv(s):find("N/A", 1, true))
end)
check("missing tcp.stream does not crash", function()
    local m, c = instance({ ["tcp.stream"] = true })
    local s = m.new_state(); feed(m, c, s, 0, 1)
    -- 无论提供什么报文字段，模拟提取器都按缺失处理。
    assert(s.packets == 0 and s.skipped == 1 and #m.snapshot(s) == 0)
end)
check("disabled sequence analysis cannot claim LOW/zero anomalies", function()
    context.sequence = false
    local row = module.snapshot(state)[1]
    assert(row.retransmissions == nil and row.zero_window == nil)
    assert(row.score_partial and row.risk == "UNKNOWN")
    context.sequence = true
end)
check("multi-TCP-layer frame is skipped instead of mixing streams", function()
    feed(module, context, state, 1, 5, { ["tcp.stream"] = { 1, 2 } })
    assert(state.skipped == 1 and state.packets == 4)
end)
check("full rescan and explicit tap.reset both clear stale streams", function()
    feed(module, context, state, 20, 1)
    assert(state.packets == 1 and #module.snapshot(state) == 1)
    local s, tap = module.listen(function() end)
    feed(module, context, s, 1, 1)
    tap.reset()
    assert(s.packets == 0 and #module.snapshot(s) == 0)
end)
check("filesystem errors are returned without crashing", function()
    local original_io = env.io
    env.io = { open = function() return nil, "permission denied" end }
    local ok, problem = module.export(state, "unwritable.csv")
    assert(not ok and problem == "permission denied")
    assert(not module.export(state, "bad\0path"))
    env.io = original_io
end)
check("existing export destination is left unchanged", function()
    local closed, writes = false, 0
    local original_io = env.io
    env.io = { open = function(path, mode)
        assert(mode == "rb"); writes = writes + 1
        return { close = function() closed = true end }
    end }
    assert(not module.export(state, "existing.csv"))
    assert(closed and writes == 1)
    env.io = original_io
end)
check("headless load does not register GUI or apply filters", function()
    local m, c = instance(nil, true)
    assert(c.menus == 0 and not m.apply_stream(m.new_state(), "0"))
end)
check("duplicate plugin loads reuse one registration", function()
    assert(loader() == module and context.menus == 1)
end)
check("GUI buttons, empty capture, close cleanup and late dialog", function()
    local m, c = instance()
    m.open_window()
    assert(c.text:find("No aggregatable TCP streams", 1, true))
    c.buttons["Apply stream..."](); local late = c.dialog
    c.buttons["Refresh"]()
    c.close(); assert(c.removed)
    late("1"); assert(c.filters == 0)
end)
print("FlowLens unit tests: " .. passed .. " passed")
