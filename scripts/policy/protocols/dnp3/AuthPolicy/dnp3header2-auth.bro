
@load frameworks/communication/listen
#@load /usr/local/bro/share/bro/base/event.bif.bro

## [16] =  "LOCAL0",
## [17] =  "LOCAL1",
## [18] =  "LOCAL2",
## [19] =  "LOCAL3",
## [20] =  "LOCAL4",
## [21] =  "LOCAL5",
## [22] =  "LOCAL6",
## [23] =  "LOCAL7",


#redef Communication::listen_port = 47758/tcp;

# Redef this to T if you want to use SSL.
#redef Communication::listen_ssl = F;

# Set the SSL certificates being used to something real if you are using encryption.
#redef ssl_ca_certificate   = "<path>/ca_cert.pem";
#redef ssl_private_key      = "<path>/bro.pem";


module ModuleDNP3Auth;

export {
        redef enum Log::ID += { DNP3Auth };
        type DNP3AuthInfo: record {
                ts: time &log;
                conIndex: count &default = 0 &log;
                alertIndex: count &default = 0 &log;
        };
}


#global cc: connection; 
#global gStart: time;
global gConIndex: count = 1;
#global dnp3_log = open_log_file("dnp3");
#global pong: event(conIndex:count);
global reqFc: count = 0xff;
global foundSSH: bool = F;
global foundRead: bool = F;
global gAlertIndex: count = 0;  ## 0 means no error, 1 means no ssh, 2 means no read op
global gUsrID: count = 1; 
global gSyslogTime: time;

global gLastSyslog: time;
global constInterval: double = 1.0;
global findSyslog: bool = F; 

##global authLog = open_log_file("authLog");


event bro_init() 
        {
	Log::disable_stream(Conn::LOG);
	Log::disable_stream(Notice::POLICY_LOG);
	Log::disable_stream(PacketFilter::LOG);
	Log::disable_stream(Syslog::LOG);
	
	Log::create_stream(ModuleDNP3Auth::DNP3Auth, [$columns=DNP3AuthInfo]);

        }

redef record connection +={
        dnp3AuthLog: DNP3AuthInfo &optional;
        };


event syslog_message(c: connection, facility: count, severity: count, msg: string)
        {
	


	if(facility >= 16 && facility <= 18){
		gUsrID = facility;
		findSyslog = T ;
	#	print fmt("syslog %d     %d", facility, gConIndex);
	}
	
	#gLastSyslog = gSyslogTime ;
	}

event dnp3_header_block(c: connection, is_orig: bool, start: count, len: count, ctrl: count, dest_addr: count, src_addr: count)
	{
        #print fmt("dnp3tcp header. start: %x, length: %x, ctrl: %x, dest_addr: %x, src_addr: %x ", start, len, ctrl, dest_addr, src_addr);
	#if(c$id$orig_h == 192.168.80.33)
        #        print fmt("connection from 192.168.80.33");
        #if(c$id$orig_h == 192.168.80.233)
        #        print fmt("connection from 192.168.80.233");
        #if(c$id$orig_h == 192.168.80.31)
        #        print fmt("connection from 192.168.80.31");
        #if(c$id$resp_h == 192.168.80.33)
        #        print fmt("connection to 192.168.80.33");
        #if(c$id$resp_h == 192.168.80.233)
        #        print fmt("connection to 192.168.80.233");
        #if(c$id$resp_h == 192.168.80.31)
         #       print fmt("connection to 192.168.80.31");
		
        }

event dnp3_data_block(c: connection, is_orig: bool, data: string, crc: count)
	{
	#print fmt("dnp3tcp data block");
	#print hexdump(data);
        #print fmt("crc: %x", crc);
        }

event dnp3_pdu_test(c: connection, is_orig: bool, rest: string)
	{
	#print fmt("dnp3tcp pdu");
	#print hexdump(rest);
        }

#event dnp3_application_request_header(c: connection, is_orig: bool, app_control: string, fc: string)
#        {
#	print fmt("dnp3 application request header:");
#	print hexdump(app_control);
#	print hexdump(fc);
#        }
event dnp3_application_request_header(c: connection, is_orig: bool, app_control: count, fc: count)
        {
	#local ws: ModuleWS::WSInfo;
	local auth: ModuleDNP3Auth::DNP3AuthInfo;
	local currentTime: time;
	#local toSyslog: interval;

	#print fmt("dnp3 application request header: app_control: %x, fc: %x %d", app_control, fc, gConIndex);
	

	currentTime = network_time();

	#toSyslog = currentTime - gSyslogTime;
	#print fmt("%d syslog of %d occurs at %f seconds ago", gConIndex, gUsrID, toSyslog);
## no authentication generate alert index 0
	#if(interval_to_double(toSyslog) > 1.0 ){
	#	ws$ts = currentTime;
	#	ws$conIndex = gConIndex;
	#	ws$alertIndex = 0;
	#	c$wsLog = ws;
	#	Log::write(ModuleWS::WS , ws);
	#}
	#else{
		
	#if( interval_to_double(toSyslog) <= 1.0 && interval_to_double(toSyslog) >= 0.5){
	if( findSyslog ){
## read alert index 1
		if( fc == 0x01 ){
			if(gUsrID != 16){
				auth$ts = currentTime ;
				auth$conIndex = gConIndex;
				auth$alertIndex = 1 ;
				c$dnp3AuthLog = auth ;
				Log::write(ModuleDNP3Auth::DNP3Auth , auth) ;
				#print authLog, fmt("%f %d %d", currentTime, gConIndex, 1);
			}
		}

## write alert index 2
		if(fc == 0x17){
			if(gUsrID != 17){
				auth$ts = currentTime ;
				auth$conIndex = gConIndex;
				auth$alertIndex = 2 ;
				c$dnp3AuthLog = auth ;
				Log::write(ModuleDNP3Auth::DNP3Auth , auth) ;

			#	print authLog, fmt("%f %d %d", currentTime, gConIndex, 2);
			}	
		}
## execute alert index 3
		if(fc == 0x03 ){
			if(gUsrID != 18){
				#ws$ts = currentTime;
				#ws$conIndex = gConIndex;
				#ws$alertIndex = 3;
				#c$wsLog = ws;
				#Log::write(ModuleWS::WS , ws);
				auth$ts = currentTime ;
				auth$conIndex = gConIndex;
				auth$alertIndex = 3 ;
				c$dnp3AuthLog = auth ;
				Log::write(ModuleDNP3Auth::DNP3Auth , auth) ;

			#	print authLog, fmt("%f %d %d", currentTime, gConIndex, 3);
			}
		}

	#reqFc = fc;
	}
	else {
		
				auth$ts = currentTime ;
				auth$conIndex = gConIndex;
				auth$alertIndex = 0 ;
				c$dnp3AuthLog = auth ;
				Log::write(ModuleDNP3Auth::DNP3Auth , auth) ;

		#print authLog, fmt("%f %d %d", currentTime, gConIndex, 0);
	}
	
	++gConIndex;
	findSyslog = F;
	#print hexdump(app_control);
        }
event dnp3_application_response_header(c: connection, is_orig: bool, app_control: count, fc: count, iin: count)
        {
	#print fmt("dnp3 application response header: app_control: %x, fc: %x", app_control, fc);
	#print dnp3_log, fmt("dnp3 application response header: app_control: %x, fc: %x, start time: %f", app_control, fc, network_time());
	#gStart = network_time();
        #event pong(gConIndex);
	#print hexdump(app_control);
        }
event dnp3_object_header(c: connection, is_orig: bool, obj_type: count, qua_field: count, number: count, rf_low: count, rf_high: count)
        {
        #print fmt("dnp3 object header is_orig: %d, obj_type: %x, qua_field: %x, number-of-item: %x, rf_high: %x, rf_low: %x ", is_orig, obj_type, qua_field, number, rf_high, rf_low);
        }
event dnp3_response_data_object(c: connection, is_orig: bool, data_value: count)
        {
        #if(data_value != 0xff)
        #        print fmt("dnp3 response data object. data_value: %x ", data_value);
        }
#event dnp3_debug_byte(c: connection, is_orig: bool, debug: string)
#	{
#	print fmt ("debug byte ");
#	print hexdump(debug);
#	}
