global gReadFromRelay: table[count] of count = {
       [1] = 0,   [2] = 0,   [3] = 0,   [4] = 0,
       [5] = 0,   [6] = 0,   [7] = 0,   [8] = 0,
       [9] = 0,   [10] = 0, [11] = 0, [12] = 0,
   };
global gIndexFromRelay: count = 1;

global gReadFromRtac: table[count] of count = {
       [1] = 0,   [2] = 0,   [3] = 0,   [4] = 0,
       [5] = 0,   [6] = 0,   [7] = 0,   [8] = 0,
       [9] = 0,   [10] = 0, [11] = 0, [12] = 0,
   };
global gIndexFromRtac: count = 1;

global gConIndex: count = 0;
global Debug: bool = F;
#global gError: bool = F;
global gError: count = 0;


module ModuleRead;

export {
        redef enum Log::ID += { Read };
        type ReadInfo: record {
                ts: time &log;
                ConnIndex: count &default = 0 &log;
		rtac1: count &default = 0 &log;
		rtac2: count &default = 0 &log;
		rtac3: count &default = 0 &log;
		rtac4: count &default = 0 &log;
		rtac5: count &default = 0 &log;
		rtac6: count &default = 0 &log;
		rtac7: count &default = 0 &log;
		rtac8: count &default = 0 &log;
		rtac9: count &default = 0 &log;
		rtac10: count &default = 0 &log;
		rtac11: count &default = 0 &log;
		relay1: count &default = 0 &log;
		relay2: count &default = 0 &log;
		relay3: count &default = 0 &log;
		relay4: count &default = 0 &log;
		relay5: count &default = 0 &log;
		relay6: count &default = 0 &log;
		relay7: count &default = 0 &log;
		relay8: count &default = 0 &log;
		relay9: count &default = 0 &log;
		relay10: count &default = 0 &log;
		relay11: count &default = 0 &log;
        };
}

event bro_init() &priority = 5
        {
	Log::disable_stream(Conn::LOG);
        Log::disable_stream(Notice::POLICY_LOG);
        Log::disable_stream(PacketFilter::LOG);
        Log::disable_stream(HTTP::LOG);
        Log::disable_stream(DNS::LOG);
        Log::disable_stream(DPD::LOG);
        Log::disable_stream(Syslog::LOG);
        Log::disable_stream(Weird::LOG);
        Log::disable_stream(Reporter::LOG);

        Log::create_stream(ModuleRead::Read, [$columns=ReadInfo]);
        }

redef record connection += {
    readLog: ReadInfo &optional;
    };



