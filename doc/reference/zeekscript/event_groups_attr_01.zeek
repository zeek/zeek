event http_request(c: connection, method: string, original_URI: string, unescaped_URI: string, version: string) &group="http-print-debugging"
    {
        print fmt("HTTP request: %s %s (%s->%s)", method, original_URI, c$id$orig_h, c$id$resp_h);
    }

event http_header(c: connection, is_orig: bool, original_name: string, name: string, value: string) &group="http-print-debugging"
    {
    if ( name != "USER-AGENT" && name != "SERVER" )
        return;

    local snd = is_orig ? c$id$orig_h : c$id$resp_h;
    local rcv = is_orig ? c$id$resp_h : c$id$orig_h;
    print fmt("HTTP header : %s=%s (%s->%s)", original_name, value, snd, rcv);
    }

event http_reply(c: connection, version: string, code: count, reason: string) &group="http-print-debugging"
    {
        print fmt("HTTP reply: %s/%s version %s (%s->%s)", code, reason, version, c$id$resp_h, c$id$orig_h);
    }
