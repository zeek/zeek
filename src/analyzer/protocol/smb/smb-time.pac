%header{
double filetime2zeektime(uint64_t ts);
double time_from_lanman(uint32_t smb_time, uint32_t smb_date, uint16_t tz);

zeek::RecordValPtr SMB_BuildMACTimes(uint64_t modify, uint64_t access,
                                     uint64_t create, uint64_t change);
%}

%code{
double filetime2zeektime(uint64_t ts)
	{
	// Zeek can't support times back to the 1600's
	// so we subtract a lot of seconds.
	return (static_cast<double>(ts) / 10000000.0) - 11644473600.0;
	}

double time_from_lanman(uint32_t smb_time, uint32_t smb_date, uint16_t tz)
	{
	tm lTime{0};

	// Lanman uses this format for time/date:
	// https://learn.microsoft.com/en-us/cpp/c-runtime-library/32-bit-windows-time-date-formats
	// Seconds is in 2-second increments in the data.
	lTime.tm_sec = (smb_time & 0x1f) * 2;
	lTime.tm_min = (smb_time >> 5) & 0x3f;
	lTime.tm_hour = (smb_time >> 11) & 0x1f;

	lTime.tm_mday = smb_date & 0x1f;
	// tm_mon is zero-indexed, so adjust for that.
	lTime.tm_mon = ((smb_date >> 5) & 0x0f) - 1;
	// The year in the data is the number of years from 1980, while tm_year is the
	// number of years since 1900.
	lTime.tm_year = ((smb_date >> 9) & 0x7f) + 80;
	lTime.tm_isdst = -1;

#ifndef _MSC_VER
	// The timezone passed in the data is the number of minutes from UTC, while
	// tm_gmtoff is the number of seconds east of UTC. Adjust for that. This field
	// is a POSIX extension that Windows doesn't support.
	lTime.tm_gmtoff = static_cast<long>(tz) * 60;
#endif

	return timegm(&lTime);
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
