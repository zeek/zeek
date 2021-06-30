%header{
double filetime2zeektime(uint64_t ts);
double time_from_lanman(SMB_time* t, SMB_date* d, uint16_t tz);

zeek::RecordValPtr SMB_BuildMACTimes(uint64_t modify, uint64_t access,
                                     uint64_t create, uint64_t change);
%}

%code{
double filetime2zeektime(uint64_t ts)
	{
	// Zeek can't support times back to the 1600's
	// so we subtract a lot of seconds.
	return (ts / 10000000.0L) - 11644473600.0L;
	}

double time_from_lanman(SMB_time* t, SMB_date* d, uint16_t tz)
	{
	tm lTime;
	lTime.tm_sec = ${t.two_seconds} * 2;
	lTime.tm_min = ${t.minutes};
	lTime.tm_hour = ${t.hours};
	lTime.tm_mday = ${d.day};
	lTime.tm_mon = ${d.month};
	lTime.tm_year = 1980 + ${d.year};
	lTime.tm_isdst = -1;
	return mktime(&lTime) + tz;
	}

zeek::RecordValPtr SMB_BuildMACTimes(uint64_t modify, uint64_t access,
                                     uint64_t create, uint64_t change)
	{
	auto r = zeek::make_intrusive<zeek::RecordVal>(zeek::BifType::Record::SMB::MACTimes);
	r->Assign(0, filetime2zeektime(modify));
	r->Assign(1, modify);
	r->Assign(2, filetime2zeektime(access));
	r->Assign(3, access);
	r->Assign(4, filetime2zeektime(create));
	r->Assign(5, create);
	r->Assign(6, filetime2zeektime(change));
	r->Assign(7, change);
	return r;
	}
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
