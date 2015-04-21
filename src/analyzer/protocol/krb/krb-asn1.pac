
%include ../asn1/asn1.pac

%header{
    Val* GetTimeFromAsn1(const KRB_Time* atime, int64 usecs);
    Val* GetTimeFromAsn1(StringVal* atime, int64 usecs);
%}

%code{

Val* GetTimeFromAsn1(const KRB_Time* atime, int64 usecs)
	{
	StringVal* atime_bytestring = bytestring_to_val(atime->time());
	Val* result = GetTimeFromAsn1(atime_bytestring, usecs);
	Unref(atime_bytestring);
	return result;
	}

Val* GetTimeFromAsn1(StringVal* atime, int64 usecs)
	{
	time_t lResult = 0;

	char lBuffer[17];
	char* pBuffer = lBuffer;

	size_t lTimeLength = atime->Len();
	char * pString = (char *) atime->Bytes();

	if ( lTimeLength != 15 && lTimeLength != 17 )
		return 0;

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

	return new Val(double(lResult + double(usecs/100000.0)), TYPE_TIME);
	}

%}
