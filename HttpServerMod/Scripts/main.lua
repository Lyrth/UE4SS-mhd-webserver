
if not jit then
    print("Not running LuaJIT!")
    return
end

local ffi = require 'ffi'

local PORT = 8987

-- patterned from https://github.com/Karlson2k/libmicrohttpd/blob/master/doc/examples/hellobrowser.c
do
    local modPath = debug.getinfo(1, 'S').source:match('@(.+)[Ss]cripts')

    ffi.cdef(io.open(modPath .. "mhd.h"):read('*a'))
    local M = ffi.load(modPath .. "libmicrohttpd-dll.dll") ---@cast M table<any>

    -- simple templating using gsub
    local page = ([[
            <html>
                <body style="font-family: monospace;">
                    <h2>Hello from UE4SS version {ue4ss_ver}!</h2>
                    <span>UE4SS was built with {jit_ver} on {jit_os} {jit_arch}</span>
                    <br>
                    <span>Your lucky float is %.9f</span>
                </body>
            </html>
        ]]):gsub('{(.-)}', {
            ue4ss_ver = ("%d.%d.%d"):format(UE4SS.GetVersion()),
            jit_ver = jit.version,
            jit_os = jit.os,
            jit_arch = jit.arch,
        })

    -- forward declare for use with callback
    local daemon

    local answer_to_connection = function(cls, conn, url, method, ver, data, data_sz, req_cls)
        print(">>> ", ffi.string(method), ffi.string(ver), ffi.string(url))

        local pagep = page:format(math.random()) -- second pass replace %.9f

        local ret
        if ffi.string(url) == "/shutdown" then

            local resp = [[
                <html><body style="font-family: monospace;"><h2>Server is shutting down!</h2></body></head>
            ]]
            local response = M.MHD_create_response_from_buffer_static(#resp, resp)
            ret = M.MHD_queue_response(conn, 200, response)
            M.MHD_destroy_response(response)
            print("=== HTTP Server is stopping. ===")
            ExecuteWithDelay(1000, function()
                M.MHD_stop_daemon(daemon)
                print("=== HTTP Server stopped. ===")
            end)
        else

            local response = M.MHD_create_response_from_buffer_static(#pagep, pagep)
            ret = M.MHD_queue_response(conn, 200, response)
            M.MHD_destroy_response(response)
        end

        return ret
    end

    -- error handler
    M.MHD_set_panic_func(function(_,file,line,reason) print(ffi.string(file),tonumber(line),ffi.string(reason)) end, nil)

    daemon = M.MHD_start_daemon(
        bit.bor(M.MHD_USE_AUTO, M.MHD_USE_INTERNAL_POLLING_THREAD),
        PORT, nil, nil,
        answer_to_connection, nil, M.MHD_OPTION_END)
    assert(daemon ~= nil, "Cannot create daemon!")

    print()
    print("=== HTTP Server started on localhost:"..PORT.." ===")
    print()
end
