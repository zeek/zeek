@load base/protocols/conn/removal-hooks

module RESP;

export {
    ## Log stream identifier.
    redef enum Log::ID += { LOG };

    ## The ports to register RESP for.
    const ports = {
        6379/tcp,
    } &redef;

    type SetCommand: record {
        key: string &log;
        value: string &log;
        nx: bool;
        xx: bool;
        get: bool;
        ex: count &optional;
        px: count &optional;
        exat: count &optional;
        pxat: count &optional;
        keep_ttl: bool;
    };

    type GetCommand: record {
        key: string &log;
    };

    type Command: record {
        ## The raw command, exactly as parsed
        raw: vector of string &log;
        ## The key, if this command is known to have a key
        key: string &log &optional;
        ## The value, if this command is known to have a value
        value: string &log &optional;
    };

    ## Record type containing the column fields of the RESP log.
    type Info: record {
        ## Timestamp for when the activity happened.
        ts: time &log;
        ## Unique ID for the connection.
        uid: string &log;
        ## The connection's 4-tuple of endpoint addresses/ports.
        id: conn_id &log;
        ## The Redis command
        cmd: Command &log;
    };

    ## A default logging policy hook for the stream.
    global log_policy: Log::PolicyHook;

    ## Default hook into RESP logging.
    global log_resp: event(rec: Info);
}

redef record connection += {
    redis_resp: Info &optional;
};

redef likely_server_ports += { ports };

# TODO: If you're going to send file data into the file analysis framework, you
# need to provide a file handle function. This is a simple example that's
# sufficient if the protocol only transfers a single, complete file at a time.
#
# function get_file_handle(c: connection, is_orig: bool): string
#   {
#   return cat(Analyzer::ANALYZER_SPICY_RESP, c$start_time, c$id, is_orig);
#   }

event zeek_init() &priority=5
    {
    Log::create_stream(RESP::LOG, [$columns=Info, $ev=log_resp, $path="resp", $policy=log_policy]);

    Analyzer::register_for_ports(Analyzer::ANALYZER_SPICY_RESP, ports);

    # TODO: To activate the file handle function above, uncomment this.
    # Files::register_protocol(Analyzer::ANALYZER_SPICY_RESP, [$get_file_handle=RESP::get_file_handle ]);
    }

# Initialize logging state.
hook set_session(c: connection, cmd: Command)
    {
    if ( c?$redis_resp )
        return;

    c$redis_resp = Info($ts=network_time(), $uid=c$uid, $id=c$id, $cmd=cmd);
    }

function emit_log(c: connection)
    {
    if ( ! c?$redis_resp )
        return;

    Log::write(RESP::LOG, c$redis_resp);
    delete c$redis_resp;
    }

event RESP::command(c: connection, is_orig: bool, command: Command)
    {
    hook set_session(c, command);

    local info = c$redis_resp;
    emit_log(c);
    }
