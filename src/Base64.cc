// $Id: Base64.cc 6024 2008-07-26 19:20:47Z vern $

#include "config.h"
#include "Base64.h"

static int base64_table[256];

static void init_base64_table()
	{
	static int table_initialized = 0;

	if ( ++table_initialized > 1 )
		return;

	int i;
	for ( i = 0; i < 256; ++i )
		base64_table[i] = -1;

	for ( i = 0; i < 26; ++i )
		{
		base64_table['A' + i] = i;
		base64_table['a' + i] = i + 26;
		}

	for ( i = 0; i < 10; ++i )
		base64_table['0' + i] = i + 52;

	// Casts to avoid compiler warnings.
	base64_table[int('+')] = 62;
	base64_table[int('/')] = 63;
	base64_table[int('=')] = 0;
	}

Base64Decoder::Base64Decoder(Analyzer* arg_analyzer)
	{
	init_base64_table();
	base64_group_next = 0;
	base64_padding = base64_after_padding = 0;
	errored = 0;
	analyzer = arg_analyzer;
	}

int Base64Decoder::Decode(int len, const char* data, int* pblen, char** pbuf)
	{
	int blen;
	char* buf;

	if ( ! pbuf )
		internal_error("nil pointer to decoding result buffer");

	if ( *pbuf )
		{
		buf = *pbuf;
		blen = *pblen;
		}
	else
		{
		// Estimate the maximal number of 3-byte groups needed,
		// plus 1 byte for the optional ending NUL.
		blen = int((len + base64_group_next + 3) / 4) * 3 + 1;
		*pbuf = buf = new char[blen];
		}

	int dlen = 0;

	while ( 1 )
		{
		if ( base64_group_next == 4 )
			{
			// For every group of 4 6-bit numbers,
			// write the decoded 3 bytes to the buffer.
			if ( base64_after_padding )
				{
				if ( ++errored == 1 )
					IllegalEncoding("extra base64 groups after '=' padding are ignored");
				base64_group_next = 0;
				continue;
				}

			int num_octets = 3 - base64_padding;

			if ( buf + num_octets > *pbuf + blen )
				break;

			uint32 bit32 =
				((base64_group[0] & 0x3f) << 18) |
				((base64_group[1] & 0x3f) << 12) |
				((base64_group[2] & 0x3f) << 6)  |
				((base64_group[3] & 0x3f));

			if ( --num_octets >= 0 )
				*buf++ = char((bit32 >> 16) & 0xff);

			if ( --num_octets >= 0 )
				*buf++ = char((bit32 >> 8) & 0xff);

			if ( --num_octets >= 0 )
				*buf++ = char((bit32) & 0xff);

			if ( base64_padding > 0 )
				base64_after_padding = 1;

			base64_group_next = 0;
			base64_padding = 0;
			}

		if ( dlen >= len )
			break;

		if ( data[dlen] == '=' )
			++base64_padding;

		int k = base64_table[(unsigned char) data[dlen]];
		if ( k >= 0 )
			base64_group[base64_group_next++] = k;
		else
			{
			if ( ++errored == 1 )
				IllegalEncoding(fmt("character %d ignored by Base64 decoding", (int) (data[dlen])));
			}

		++dlen;
		}

	*pblen = buf - *pbuf;
	return dlen;
	}

int Base64Decoder::Done(int* pblen, char** pbuf)
	{
	const char* padding = "===";

	if ( base64_group_next != 0 )
		{
		if ( base64_group_next < 4 )
			IllegalEncoding(fmt("incomplete base64 group, padding with %d bits of 0", (4-base64_group_next) * 6));
		Decode(4 - base64_group_next, padding, pblen, pbuf);
		return -1;
		}

	if ( pblen )
		*pblen = 0;

	return 0;
	}

BroString* decode_base64(const BroString* s)
	{
	int buf_len = int((s->Len() + 3) / 4) * 3 + 1;
	int rlen2, rlen = buf_len;
	char* rbuf2, *rbuf = new char[rlen];

	Base64Decoder dec(0);
	if ( dec.Decode(s->Len(), (const char*) s->Bytes(), &rlen, &rbuf) == -1 )
		goto err;

	rlen2 = buf_len - rlen;
	rbuf2 = rbuf + rlen;
	// Done() returns -1 if there isn't enough padding, but we just ignore
	// it.
	dec.Done(&rlen2, &rbuf2);
	rlen += rlen2;

	rbuf[rlen] = '\0';
	return new BroString(1, (u_char*) rbuf, rlen);

err:
	delete [] rbuf;
	return 0;
	}
