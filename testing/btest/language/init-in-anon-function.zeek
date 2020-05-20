# @TEST-EXEC: zeek -r ${TRACES}/wikipedia.trace  %INPUT >out
# @TEST-EXEC: btest-diff http.log

module Foo;

event zeek_init() {

    Log::remove_default_filter(HTTP::LOG);

    local filter: Log::Filter = [$name = "http", 
                                 $pred = function(rec: HTTP::Info): bool {
                                    rec$id$orig_h = remask_addr(rec$id$orig_h, 0.0.0.0, 112);
                                    return T;
                                 }];
    Log::add_filter(HTTP::LOG, filter);
}
