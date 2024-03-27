// Copyright (c) 2023 by the Zeek Project. See COPYING for details.

#include <hilti/rt/libhilti.h>

#include "zeek/Desc.h"
#include "zeek/file_analysis/Manager.h"
#include "zeek/spicy/cookie.h"
#include "zeek/spicy/runtime-support.h"

std::string ssl_get_certificate_fuid(const hilti::rt::Bool& is_client, const hilti::rt::integer::safe<uint32_t>& pos) {
    auto cookie = static_cast<zeek::spicy::rt::Cookie*>(hilti::rt::context::cookie());
    assert(cookie);

    auto c = cookie->protocol;
    if ( ! c )
        throw zeek::spicy::rt::ValueUnavailable("connection not available");

    zeek::ODesc file_handle;
    file_handle.AddRaw("Analyzer::ANALYZER_SSL");
    file_handle.Add(c->analyzer->Conn()->StartTime());
    file_handle.AddRaw(is_client ? "T" : "F", 1);
    c->analyzer->Conn()->IDString(&file_handle);

    file_handle.Add((uint32_t)pos);
    std::string file_id = zeek::file_mgr->HashHandle(file_handle.Description());
    return file_id;
}

std::string ssl_get_ocsp_fuid() {
    auto cookie = static_cast<zeek::spicy::rt::Cookie*>(hilti::rt::context::cookie());
    assert(cookie);

    auto c = cookie->protocol;
    if ( ! c )
        throw zeek::spicy::rt::ValueUnavailable("connection not available");

    zeek::ODesc file_handle;
    file_handle.AddRaw("Analyzer::ANALYZER_SSL");
    file_handle.Add(c->analyzer->Conn()->StartTime());
    file_handle.AddRaw("F");
    c->analyzer->Conn()->IDString(&file_handle);
    file_handle.Add("ocsp");
    std::string file_id = zeek::file_mgr->HashHandle(file_handle.Description());
    return file_id;
}
