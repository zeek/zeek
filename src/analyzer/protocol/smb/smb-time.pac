function SMB_BuildMACTimes(modify: uint64, access: uint64, create: uint64, change: uint64): BroVal
	%{
	RecordVal* r = new RecordVal(BifType::Record::SMB::MACTimes);

	r->Assign(0, filetime2brotime(modify));
	r->Assign(1, filetime2brotime(access));
	r->Assign(2, filetime2brotime(create));
	r->Assign(3, filetime2brotime(change));

	return r;
	%}

function filetime2brotime(ts: uint64): Val
	%{
	double secs = (ts / 10000000.0);

	// Bro can't support times back to the 1600's 
	// so we subtract a lot of seconds.
	Val* bro_ts = new Val(secs - 11644473600.0, TYPE_TIME);
	
	return bro_ts;
	%}

type SMB_timestamp32 = uint32;
type SMB_timestamp = uint64;

type SMB_time = record {
	two_seconds : uint16;
	minutes     : uint16;
	hours       : uint16;
} &byteorder = littleendian;

type SMB_date = record {
	day   : uint16;
	month : uint16;
	year  : uint16;
} &byteorder = littleendian;


#type SMB2_timestamp = record {
#	lowbits           : uint32;
#	highbits          : uint32;
#} &byteorder = littleendian;
#