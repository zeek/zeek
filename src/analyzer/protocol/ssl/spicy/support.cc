// See the file "COPYING" in the main distribution directory for copyright.

#include <hilti/rt/libhilti.h>
#include <cassert>

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

    file_handle.Add(pos.Ref());
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

// TODO: it would make sense to make this available for all users of Spicy
bool ssl_is_partial_tcp() {
    auto cookie = static_cast<zeek::spicy::rt::Cookie*>(hilti::rt::context::cookie());
    assert(cookie);

    auto x = cookie->protocol;
    if ( ! x || ! x->analyzer )
        return false;

    auto* tcp = dynamic_cast<zeek::analyzer::tcp::TCP_ApplicationAnalyzer*>(x->analyzer);
    if ( ! tcp )
        return false;

    if ( tcp->TCP() && tcp->TCP()->IsPartial() )
        return true;

    return false;
}
