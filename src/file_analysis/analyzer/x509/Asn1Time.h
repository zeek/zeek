static double GetTimeFromAsn1(const ASN1_TIME* atime, const char* arg_fid, Reporter* reporter)
	{
	const char *fid = arg_fid ? arg_fid : "";
	time_t lResult = 0;

	char lBuffer[26];
	char* pBuffer = lBuffer;

	const char *pString = (const char *) atime->data;
	unsigned int remaining = atime->length;

	if ( atime->type == V_ASN1_UTCTIME )
		{
		if ( remaining < 11 || remaining > 17 )
			{
			reporter->Weird(fmt("Could not parse time in X509 certificate (fuid %s) -- UTCTime has wrong length", fid));
			return 0;
			}

		if ( pString[remaining-1] != 'Z' )
			{
			// not valid according to RFC 2459 4.1.2.5.1
			reporter->Weird(fmt("Could not parse UTC time in non-YY-format in X509 certificate (x509 %s)", fid));
			return 0;
			}

		// year is first two digits in YY format. Buffer expects YYYY format.
		if ( pString[0] < '5' ) // RFC 2459 4.1.2.5.1
			{
			*(pBuffer++) = '2';
			*(pBuffer++) = '0';
			}
		else
			{
			*(pBuffer++) = '1';
			*(pBuffer++) = '9';
			}

		memcpy(pBuffer, pString, 10);
		pBuffer += 10;
		pString += 10;
		remaining -= 10;
		}
	else if ( atime->type == V_ASN1_GENERALIZEDTIME )
		{
		// generalized time. We apparently ignore the YYYYMMDDHH case
		// for now and assume we always have minutes and seconds.
		// This should be ok because it is specified as a requirement in RFC 2459 4.1.2.5.2

		if ( remaining < 12 || remaining > 23 )
			{
			reporter->Weird(fmt("Could not parse time in X509 certificate (fuid %s) -- Generalized time has wrong length", fid));
			return 0;
			}

		memcpy(pBuffer, pString, 12);
		pBuffer += 12;
		pString += 12;
		remaining -= 12;
		}
	else
		{
		reporter->Weird(fmt("Invalid time type in X509 certificate (fuid %s)", fid));
		return 0;
		}

	if ( (remaining == 0) || (*pString == 'Z') || (*pString == '-') || (*pString == '+') )
		{
		*(pBuffer++) = '0';
		*(pBuffer++) = '0';
		}

	else if ( remaining >= 2 )
		{
		*(pBuffer++) = *(pString++);
		*(pBuffer++) = *(pString++);

		remaining -= 2;

		// Skip any fractional seconds...
		if ( (remaining > 0) && (*pString == '.') )
			{
			pString++;
			remaining--;

			while ( (remaining > 0) && (*pString >= '0') && (*pString <= '9') )
				{
				pString++;
				remaining--;
				}
			}
		}

	else
		{
		reporter->Weird(fmt("Could not parse time in X509 certificate (fuid %s) -- additional char after time", fid));
		return 0;
		}

	*(pBuffer++) = 'Z';
	*(pBuffer++) = '\0';

	time_t lSecondsFromUTC;

	if ( remaining == 0 || *pString == 'Z' )
		lSecondsFromUTC = 0;
	else
		{
		if ( remaining < 5 )
			{
			reporter->Weird(fmt("Could not parse time in X509 certificate (fuid %s) -- not enough bytes remaining for offset", fid));
			return 0;
			}

		if ((*pString != '+') && (*pString != '-'))
			{
			reporter->Weird(fmt("Could not parse time in X509 certificate (fuid %s) -- unknown offset type", fid));
			return 0;
			}

		lSecondsFromUTC = ((pString[1] - '0') * 10 + (pString[2] - '0')) * 60;
		lSecondsFromUTC += (pString[3] - '0') * 10 + (pString[4] - '0');

		if (*pString == '-')
			lSecondsFromUTC = -lSecondsFromUTC;
		}

	tm lTime;
	lTime.tm_sec  = ((lBuffer[12] - '0') * 10) + (lBuffer[13] - '0');
	lTime.tm_min  = ((lBuffer[10] - '0') * 10) + (lBuffer[11] - '0');
	lTime.tm_hour = ((lBuffer[8] - '0') * 10) + (lBuffer[9] - '0');
	lTime.tm_mday = ((lBuffer[6] - '0') * 10) + (lBuffer[7] - '0');
	lTime.tm_mon  = (((lBuffer[4] - '0') * 10) + (lBuffer[5] - '0')) - 1;
	lTime.tm_year = (lBuffer[0] - '0') * 1000 + (lBuffer[1] - '0') * 100 + ((lBuffer[2] - '0') * 10) + (lBuffer[3] - '0');

	if ( lTime.tm_year > 1900)
		lTime.tm_year -= 1900;

	lTime.tm_wday = 0;
	lTime.tm_yday = 0;
	lTime.tm_isdst = 0;  // No DST adjustment requested

	lResult = mktime(&lTime);

	if ( lResult )
		{
		if ( lTime.tm_isdst  != 0 )
			lResult -= 3600;  // mktime may adjust for DST  (OS dependent)

		lResult += lSecondsFromUTC;
		}

	else
		lResult = 0;

	return lResult;
}
