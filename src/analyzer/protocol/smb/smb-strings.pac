function uint8s_to_stringval(s: uint8[]): StringVal
	%{
	int length = 0;

	const char* sp;
	bool ascii = true;

	vector<uint8>* data = s;
	length = data->size();
	// Scan the string once to see if it's all ascii
	// embedded in UCS-2 (16 bit unicode).
	for( int i = 1; i < length; i=i+2 )
		{
		// Find characters in odd positions that aren't null.
		if ( (*data)[i] != 0x00 )
			{
			ascii = false;
			break;
			}
		}

	char *buf = new char[length];

	for ( int i = 0; i < length; i=i+2)
		{
		if ( ascii )
			{
			int j = i/2;
			buf[j] = (*data)[i];
			}
		else
			{
			// Flip the bytes because they are transferred in little endian.
			buf[i] = (*data)[i+1];
			buf[i+1] = (*data)[i];
			}
		}

	if ( ascii )
		{
		length = length / 2;
		if ( length > 0 && buf[length-1] == 0x00 )
			--length;
		}
	else if ( length >= 2 && buf[length-1] == 0 && buf[length-2] == 0 )
		{
		// If the last 2 bytes are nulls, cut them with the length.
		length = length-2;
		}
	StringVal *output = new StringVal(length, buf);
	delete [] buf;
	return output;
	%}

function extract_string(s: SMB_string) : StringVal
	%{
	int length = 0;

	const char* sp;
	bool ascii = true;

	if ( s->val_case_index() == 0 )
		{
		length = s->a()->size();
		char *buf = new char[length];

		for ( int i = 0; i < length; i++)
			{
			unsigned char t = (*(s->a()))[i];
			buf[i] = t;
			}

		if ( length > 0 && buf[length-1] == 0x00 )
			length--;

		StringVal *ret = new StringVal(length, buf);
		delete [] buf;
		return ret;
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

type SMB_ascii_string = uint8[] &until($element == 0x00);

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
};

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
