# @TEST-EXEC: zeek -b -Cr $TRACES/tcp/tcp_options_after_eol.pcap %INPUT >out
# @TEST-EXEC: btest-diff weird.log
# @TEST-EXEC: btest-diff out

@load base/frameworks/notice/weird.zeek

event tcp_options (c: connection, is_orig: bool, options: TCP::OptionList)
	{
        for ( i in options ) {
            local data: string = "";
            if ( options[i]?$data )
                data = options[i]$data;

            print(fmt("Option kind=%d, len=%d, data=%s", options[i]$kind, options[i]$length, data));
	    }
    }
