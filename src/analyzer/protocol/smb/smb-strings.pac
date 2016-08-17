
refine connection SMB_Conn += {
	%member{
		SMB_unicode_string *me;
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

	function uint8s_to_stringval(data: uint8[]): StringVal
		%{
		int length = data->size();
		uint8 buf[length];

		for ( int i = 0; i < length; ++i)
			buf[i] = (*data)[i];

		const bytestring bs = bytestring(buf, length);
		return utf16_bytestring_to_utf8_val(bro_analyzer()->Conn(), bs);
		%}

	function extract_string(s: SMB_string) : StringVal
		%{
		if ( s->unicode() == false )
			{
			int length = s->a()->size();
			char buf[length];

			for ( int i = 0; i < length; i++)
				{
				unsigned char t = (*(s->a()))[i];
				buf[i] = t;
				}

			if ( length > 0 && buf[length-1] == 0x00 )
				length--;

			return new StringVal(length, buf);
			}
		else
			{
			return uint8s_to_stringval(s->u()->s());
			}
		%}

	function smb_string2stringval(s: SMB_string) : StringVal
		%{
		return extract_string(s);
		%}

	function smb2_string2stringval(s: SMB2_string) : StringVal
		%{
		return uint8s_to_stringval(s->s());
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
