#### Including different event for response objects


#@load /home/hugo/experiment/dnp3/policy/ReadSpec/dnp3headers.bro
@load /home/hugo/experiment/DNP3Analyzer/intPolicy/dnp3headers3.bro


module ModuleDetect;

export {
        redef enum Log::ID += { Detect };
        type DetectInfo: record {
                ts: time &log;
                ConnIndex: count &default = 0 &log;
                DetectID: count &default = 0 &log;
        };
}

event bro_init() &priority = 5
        {
        Log::create_stream(ModuleDetect::Detect, [$columns=DetectInfo]);
        }

redef record connection += {
    detectLog: DetectInfo &optional;
    };

event dnp3_analog_input32_woFlag(c: connection, is_orig: bool, value: count)
	{
	local tempMsg: string;
	local detect: ModuleDetect::DetectInfo;
	local read: ModuleRead::ReadInfo;

        #print fmt("dnp3 response analog 32 bit without flag. is_orig: %x   value: %x   conIndex: %d ", is_orig, value, gConIndex);
	#if( ( c$id$orig_h == 192.168.80.233 ) && ( is_orig == F ) ){
	if( ( c$id$orig_h == 192.168.80.30 ) && ( is_orig == F ) ){
		# print fmt("response from relay");
		gReadFromRelay[gIndexFromRelay] = value;
		++gIndexFromRelay;
		if(gIndexFromRelay == 12){
		
			#tempMsg = fmt("%d %d %d %d %d", gReadFromRelay[1], gReadFromRelay[2], 
			#	gReadFromRelay[3], gReadFromRelay[4], gReadFromRelay[5]);	
			#NOTICE([$note=FromRelayLog, $msg=tempMsg, $conn=c]);
			#read$ts = network_time();
			#read$ConnIndex = gConIndex;
			#read$relay1 = gReadFromRelay[1];
			#read$relay2 = gReadFromRelay[2];
			#read$relay3 = gReadFromRelay[3];
			#read$relay4 = gReadFromRelay[4];
			#read$relay5 = gReadFromRelay[5];
			#read$relay6 = gReadFromRelay[6];
			#read$relay7 = gReadFromRelay[7];
			#read$relay8 = gReadFromRelay[8];
			#read$relay9 = gReadFromRelay[9];
			#read$relay10 = gReadFromRelay[10];
			#read$relay11 = gReadFromRelay[11];
			#c$readLog = read;
			#Log::write(ModuleRead::Read, read);
				
			gIndexFromRelay = 1;
		}

	}
	if( ( c$id$orig_h == 192.168.80.233 ) && (is_orig == F ) ){
	#if( ( c$id$resp_h == 192.168.80.233 ) && (is_orig == F ) ){
		#print fmt("response to hmi");
		gReadFromRtac[gIndexFromRtac] = value;
		++gIndexFromRtac;
	}
	if(gIndexFromRtac == 12){
		if(Debug) print fmt("comparing two sets of reading measurement");
		gIndexFromRtac = 1;
		#gIndexFromRelay = 1;
		
		#tempMsg = fmt("%d %d %d %d %d", gReadFromRtac[1], gReadFromRtac[2], 
		#		gReadFromRtac[3], gReadFromRtac[4], gReadFromRtac[5]);	
		#NOTICE([$note=FromRtacLog, $msg=tempMsg, $conn=c]);
		read$ts = network_time();
		read$ConnIndex = gConIndex;
		read$relay1 = gReadFromRelay[1];
		read$relay2 = gReadFromRelay[2];
		read$relay3 = gReadFromRelay[3];
		read$relay4 = gReadFromRelay[4];
		read$relay5 = gReadFromRelay[5];
		read$relay6 = gReadFromRelay[6];
		read$relay7 = gReadFromRelay[7];
		read$relay8 = gReadFromRelay[8];
		read$relay9 = gReadFromRelay[9];
		read$relay10 = gReadFromRelay[10];
		read$relay11 = gReadFromRelay[11];

		read$rtac1 = gReadFromRtac[1];
		read$rtac2 = gReadFromRtac[2];
		read$rtac3 = gReadFromRtac[3];
		read$rtac4 = gReadFromRtac[4];
		read$rtac5 = gReadFromRtac[5];
		read$rtac6 = gReadFromRtac[6];
		read$rtac7 = gReadFromRtac[7];
		read$rtac8 = gReadFromRtac[8];
		read$rtac9 = gReadFromRtac[9];
		read$rtac10 = gReadFromRtac[10];
		read$rtac11 = gReadFromRtac[11];
		c$readLog = read;
		Log::write(ModuleRead::Read, read);

		if(gReadFromRelay[1] != gReadFromRtac[1]){
			gError = 1;		
		}
		else if(gReadFromRelay[2] != gReadFromRtac[2]){
                        gError = 2;
                }
		else if(gReadFromRelay[3] != gReadFromRtac[3]){
                        gError = 3;
                }
		else if(gReadFromRelay[4] != gReadFromRtac[4]){
                        gError = 4;
                }
		else if(gReadFromRelay[5] != gReadFromRtac[5]){
                        gError = 5;
                }
		else if(gReadFromRelay[6] != gReadFromRtac[6]){
                        gError = 6;
                }	
		else if(gReadFromRelay[7] != gReadFromRtac[7]){
                        gError = 7;
                }
		else if(gReadFromRelay[8] != gReadFromRtac[8]){
                        gError = 8;
                }
		else if(gReadFromRelay[9] != gReadFromRtac[9]){
                        gError = 9;
                }
		else if(gReadFromRelay[10] != gReadFromRtac[10]){
                        gError = 10;
                }
		else if(gReadFromRelay[11] != gReadFromRtac[11]){
                        gError = 11;
                }
		else{
			gError = 0;
		}
		if(gError != 0){
			#tempMsg =  fmt("%d", gConIndex);
			#NOTICE([$note=ReadCompromise,
			#	$msg=tempMsg,
			#	$conn=c]);
			#c$conn$AnaInRelay_1 = gReadFromRelay[1];
		        #c$conn$AnaInRtac_1 = gReadFromRtac[1];	
			detect$ts = network_time();
			detect$ConnIndex = gConIndex;
			detect$DetectID = gError;
			c$detectLog = detect;
			Log::write(ModuleDetect::Detect, detect);
				
			gError = 0;
		}
		++gConIndex;
	}
        }




