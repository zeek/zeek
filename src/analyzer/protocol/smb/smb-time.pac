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
	// Bro can't support times back to the 1600's
	// so we subtract a lot of seconds.
	double secs = (ts / 10000000.0L) - 11644473600.0L;

	Val* bro_ts = new Val(secs, TYPE_TIME);

	return bro_ts;
	%}

function time_from_lanman(t: SMB_time, d: SMB_date, tz: uint16): Val
	%{
	tm lTime;
	lTime.tm_sec = ${t.two_seconds} * 2;
	lTime.tm_min = ${t.minutes};
	lTime.tm_hour = ${t.hours};
	lTime.tm_mday = ${d.day};
	lTime.tm_mon = ${d.month};
	lTime.tm_year = 1980 + ${d.year};
    lTime.tm_isdst = -1;
	double lResult = mktime(&lTime);
	return new Val(lResult + tz, TYPE_TIME);
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
