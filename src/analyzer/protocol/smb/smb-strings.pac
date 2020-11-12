%extern{
#include "zeek/binpac_zeek.h"
%}

%code{
zeek::StringValPtr binpac::SMB::SMB_Conn::uint8s_to_stringval(std::vector<uint8_t>* data)
	{
	int length = data->size();
	auto buf = std::make_unique<uint8[]>(length);

	for ( int i = 0; i < length; ++i)
		buf[i] = (*data)[i];

	const bytestring bs = bytestring(buf.get(), length);
	return utf16_to_utf8_val(zeek_analyzer()->Conn(), bs);
	}

zeek::StringValPtr binpac::SMB::SMB_Conn::extract_string(SMB_string* s)
	{
	if ( s->unicode() == false )
		{
		int length = s->a()->size();
		auto buf = std::make_unique<char[]>(length);

		for ( int i = 0; i < length; i++)
			{
			unsigned char t = (*(s->a()))[i];
			buf[i] = t;
			}

		if ( length > 0 && buf[length-1] == 0x00 )
			length--;

		return zeek::make_intrusive<zeek::StringVal>(length, buf.get());
		}
	else
		return uint8s_to_stringval(s->u()->s());
	}

zeek::StringValPtr binpac::SMB::SMB_Conn::smb_string2stringval(SMB_string* s)
	{
	return extract_string(s);
	}

zeek::StringValPtr binpac::SMB::SMB_Conn::smb2_string2stringval(SMB2_string* s)
	{
	return uint8s_to_stringval(s->s());
	}
%}

refine connection SMB_Conn += {
	%member{
		zeek::StringValPtr uint8s_to_stringval(std::vector<uint8_t>* data);
		zeek::StringValPtr extract_string(SMB_string* s);
		zeek::StringValPtr smb_string2stringval(SMB_string* s);
		zeek::StringValPtr smb2_string2stringval(SMB2_string* s);

		SMB_unicode_string* me;
	%}

	%init{
		me = 0;
	%}

	function store_this_unicode_string(s: SMB_unicode_string): bool
		%{
		me = s;
		return true;
		%}

	function get_prev_elem(): uint8
		%{
		if ( me && (me->s()->size() & 1) == 0 && me->s()->size() > 1 )
			{
			return me->s()->at(me->s()->size() - 2);
			}
		else
			return 0xFF;
		%}
};

type SMB_ascii_string = uint8[] &until($element == 0x00);

type SMB_unicode_string(offset: int) = record {
	pad : uint8[offset & 1] &let {
		# Save off a pointer to this string instance.
		prev: bool = $context.connection.store_this_unicode_string(this);
	};
	# Access the end of the string stored in this instance
	# to see if the previous character was a null.
	s   : uint8[] &until($element == 0x00 && $context.connection.get_prev_elem() == 0x00);
} &byteorder=littleendian;

type SMB_string(unicode: bool, offset: int) = case unicode of {
	true  -> u: SMB_unicode_string(offset);
	false -> a: SMB_ascii_string;
};

type SMB2_string(len: int) = record {
	s : uint8[len];
};
