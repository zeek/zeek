# @TEST-EXEC: zeek -b -r ${TRACES}/wikipedia.trace  %INPUT >out
# @TEST-EXEC: btest-diff http.log
@load base/protocols/http

module Foo;

hook HTTP::log_policy(rec: HTTP::Info, id: Log::ID, filter: Log::Filter) {
    rec$id$orig_h = remask_addr(rec$id$orig_h, 0.0.0.0, 112);
}