
function schedule_tftp_analyzer(id: conn_id)
    {
    # Schedule the TFTP analyzer for the expected next packet coming in on different
    # ports. We know that it will be exchanged between same IPs and reuse the
    # originator's port. "Spicy_TFTP" is the Zeek-side name of the TFTP analyzer
    # (generated from "Spicy::TFTP" in tftp.evt).
    Analyzer::schedule_analyzer(id$resp_h, id$orig_h, id$orig_p, Analyzer::ANALYZER_SPICY_TFTP, 1min);
    }

event tftp::read_request(c: connection, is_orig: bool, filename: string, mode: string)
    {
    print "TFTP read request", c$id, filename, mode;
    schedule_tftp_analyzer(c$id);
    }

event tftp::write_request(c: connection, is_orig: bool, filename: string, mode: string)
    {
    print "TFTP write request", c$id, filename, mode;
    schedule_tftp_analyzer(c$id);
    }

# Add handlers for other packet types so that we see their events being generated.
event tftp::data(c: connection, is_orig: bool, block_num: count, data: string)
    {
    print "TFTP data", block_num, data;
    }

event tftp::ack(c: connection, is_orig: bool, block_num: count)
    {
    print "TFTP ack", block_num;
    }

event tftp::error(c: connection, is_orig: bool, code: count, msg: string)
    {
    print "TFTP error", code, msg;
    }
