%extern{
#include "zeek/3rdparty/ConvertUTF.h"
#include "zeek/binpac_zeek.h"
#include "zeek/util.h"
#include "zeek/Reporter.h"
#include "zeek/Val.h"
#include "zeek/RunState.h"
%}

%code{
zeek::StringValPtr utf16_to_utf8_val(zeek::Connection* conn, const bytestring& utf16)
	{
	std::string resultstring;

	size_t utf8size = (3 * utf16.length() + 1);

	if ( utf8size > resultstring.max_size() )
		{
		zeek::reporter->Weird(conn, "utf16_conversion_failed", "utf16 too long in utf16_to_utf8_val");
		// If the conversion didn't go well, return the original data.
		return to_stringval(utf16);
		}

	resultstring.resize(utf8size, '\0');

	// We can't assume that the string data is properly aligned
	// here, so make a copy.
	auto utf16_copy_buf = std::make_unique<UTF16[]>(utf16.length()); // Twice as much memory than necessary.
	auto utf16_copy = utf16_copy_buf.get();
	memset(utf16_copy, 0, sizeof(UTF16) * utf16.length()); // needs to be set to 0, otherwise we have uninitialized memory issues when utf16.length is odd.
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
		zeek::reporter->Weird(conn, "utf16_conversion_failed", "utf16 conversion failed in utf16_to_utf8_val");
		// If the conversion didn't go well, return the original data.
		return to_stringval(utf16);
		}

	*targetstart = 0;

	// We're relying on no nulls being in the string.
	//return new StringVal(resultstring.length(), (const char *) resultstring.data());
	return zeek::make_intrusive<zeek::StringVal>(resultstring.c_str());
	}
%}

function network_time(): double
	%{
	return zeek::run_state::network_time;
	%}
