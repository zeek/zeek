
%include ../asn1/asn1.pac

%header{
    zeek::ValPtr GetTimeFromAsn1(const KRB_Time* atime, int64 usecs);
    zeek::ValPtr GetTimeFromAsn1(zeek::StringVal* atime, int64 usecs);
%}

%code{

zeek::ValPtr GetTimeFromAsn1(const KRB_Time* atime, int64 usecs)
	{
	auto atime_bytestring = to_stringval(atime->time());
	auto result = GetTimeFromAsn1(atime_bytestring.get(), usecs);
	return result;
	}

zeek::ValPtr GetTimeFromAsn1(zeek::StringVal* atime, int64 usecs)
	{
	time_t lResult = 0;

	char lBuffer[17];
	char* pBuffer = lBuffer;

	size_t lTimeLength = atime->Len();
	char * pString = (char *) atime->Bytes();

	if ( lTimeLength != 15 && lTimeLength != 17 )
		return nullptr;

	if (lTimeLength == 17 )
		pString = pString + 2;

	memcpy(pBuffer, pString, 15);
	*(pBuffer+15) = '\0';

	tm lTime;
	lTime.tm_sec  = ((lBuffer[12] - '0') * 10) + (lBuffer[13] - '0');
	lTime.tm_min  = ((lBuffer[10] - '0') * 10) + (lBuffer[11] - '0');
	lTime.tm_hour = ((lBuffer[8] - '0') * 10) + (lBuffer[9] - '0');
	lTime.tm_mday = ((lBuffer[6] - '0') * 10) + (lBuffer[7] - '0');
	lTime.tm_mon  = (((lBuffer[4] - '0') * 10) + (lBuffer[5] - '0')) - 1;
	lTime.tm_year = ((lBuffer[0] - '0') * 1000) + ((lBuffer[1] - '0') * 100) + ((lBuffer[2] - '0') * 10) + (lBuffer[3] - '0') - 1900;

	lTime.tm_wday = 0;
	lTime.tm_yday = 0;
	lTime.tm_isdst = 0;

	lResult = timegm(&lTime);

	if ( !lResult )
		lResult = 0;

	return zeek::make_intrusive<zeek::TimeVal>(double(lResult + double(usecs/100000.0)));
	}

%}
