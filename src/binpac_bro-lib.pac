%extern{
#include "binpac_bro.h"
#include "util.h"
#include "Reporter.h"
#include "Val.h"
#include "ConvertUTF.h"
%}

function network_time(): double
	%{
	return ::network_time;
	%}

function utf16_bytestring_to_utf8_val(conn: Connection, utf16: bytestring): StringVal
	%{
	std::string resultstring;

	size_t utf8size = (3 * utf16.length() + 1);

	if ( utf8size > resultstring.max_size() )
		{
		reporter->Info("utf16 too long in utf16_bytestring_to_utf8_val");
		// If the conversion didn't go well, return the original data.
		return bytestring_to_val(utf16);
		}

	resultstring.resize(utf8size, '\0');

	// We can't assume that the string data is properly aligned
	// here, so make a copy.
	UTF16 utf16_copy[utf16.length()]; // Twice as much memory than necessary.
	memset(utf16_copy, 0, sizeof(utf16_copy)); // needs to be set to 0, otherwhise we have uninitialized memory issues when utf16.length is odd.
	memcpy(utf16_copy, utf16.begin(), utf16.length());

	const char* utf16_copy_end = reinterpret_cast<const char*>(utf16_copy) + utf16.length();
	const UTF16* sourcestart = utf16_copy;
	const UTF16* sourceend = reinterpret_cast<const UTF16*>(utf16_copy_end);

	UTF8* targetstart = reinterpret_cast<UTF8*>(&resultstring[0]);
	UTF8* targetend = targetstart + utf8size;

	ConversionResult res = ConvertUTF16toUTF8(&sourcestart,
	                                          sourceend,
	                                          &targetstart,
	                                          targetend,
	                                          lenientConversion);
	if ( res != conversionOK )
		{
		reporter->Weird(conn, "utf16_conversion_failed", "utf16 conversion failed in utf16_bytestring_to_utf8_val");
		// If the conversion didn't go well, return the original data.
		return bytestring_to_val(utf16);
		}

	*targetstart = 0;

	// We're relying on no nulls being in the string.
	//return new StringVal(resultstring.length(), (const char *) resultstring.data());
	return new StringVal(resultstring.c_str());
	%}
