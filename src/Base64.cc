#include "zeek-config.h"
#include "Base64.h"
#include <math.h>

int Base64Converter::default_base64_table[256];
const string Base64Converter::default_alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

void Base64Converter::Encode(int len, const unsigned char* data, int* pblen, char** pbuf)
	{
	int blen;
	char *buf;

	if ( ! pbuf )
		reporter->InternalError("nil pointer to encoding result buffer");

	if ( *pbuf && (*pblen % 4 != 0) )
		reporter->InternalError("Base64 encode buffer not a multiple of 4");

	if ( *pbuf )
		{
		buf = *pbuf;
		blen = *pblen;
		}
	else
		{
		blen = (int)(4 * ceil((double)len / 3));
		*pbuf = buf = new char[blen];
		*pblen = blen;
		}

	for ( int i = 0, j = 0; (i < len) && ( j < blen ); )
		{
			uint32_t bit32 = data[i++]  << 16;
			bit32 += (i++ < len ? data[i-1] : 0) << 8; 
			bit32 += i++ < len ? data[i-1] : 0;

			buf[j++] = alphabet[(bit32 >> 18) & 0x3f];
			buf[j++] = alphabet[(bit32 >> 12) & 0x3f];
			buf[j++] = (i == (len+2)) ? '=' : alphabet[(bit32 >> 6) & 0x3f];
			buf[j++] = (i >= (len+1)) ? '=' : alphabet[bit32 & 0x3f];
		}
	}


int* Base64Converter::InitBase64Table(const string& alphabet)
	{
	assert(alphabet.size() == 64);

	static bool default_table_initialized = false;

	if ( alphabet == default_alphabet && default_table_initialized )
		return default_base64_table;

	int* base64_table = 0;

	if ( alphabet == default_alphabet )
		{
		base64_table = default_base64_table;
		default_table_initialized = true;
		}
	else
		base64_table = new int[256];

	int i;
	for ( i = 0; i < 256; ++i )
		base64_table[i] = -1;

	for ( i = 0; i < 26; ++i )
		{
		base64_table[int(alphabet[0 + i])] = i;
		base64_table[int(alphabet[26 + i])] = i + 26;
		}

	for ( i = 0; i < 10; ++i )
		base64_table[int(alphabet[52 + i])] = i + 52;

	// Casts to avoid compiler warnings.
	base64_table[int(alphabet[62])] = 62;
	base64_table[int(alphabet[63])] = 63;
	base64_table[int('=')] = 0;

	return base64_table;
	}

Base64Converter::Base64Converter(Connection* arg_conn, const string& arg_alphabet)
	{
	if ( arg_alphabet.size() > 0 )
		{
		assert(arg_alphabet.size() == 64);
		alphabet = arg_alphabet;
		}
	else
		{
		alphabet = default_alphabet;
		}

	base64_table = 0;
	base64_group_next = 0;
	base64_padding = base64_after_padding = 0;
	errored = 0;
	conn = arg_conn;
	}

Base64Converter::~Base64Converter()
	{
	if ( base64_table != default_base64_table )
		delete [] base64_table;
	}

int Base64Converter::Decode(int len, const char* data, int* pblen, char** pbuf)
	{
	int blen;
	char* buf;

	// Initialization of table on first_time call of Decode.
	if ( ! base64_table )
		base64_table = InitBase64Table(alphabet);

	if ( ! pbuf )
		reporter->InternalError("nil pointer to decoding result buffer");

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

int Base64Converter::Done(int* pblen, char** pbuf)
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


BroString* decode_base64(const BroString* s, const BroString* a, Connection* conn)
	{
	if ( a && a->Len() != 0 && a->Len() != 64 )
		{
		reporter->Error("base64 decoding alphabet is not 64 characters: %s",
		                a->CheckString());
		return 0;
		}

	int buf_len = int((s->Len() + 3) / 4) * 3 + 1;
	int rlen2, rlen = buf_len;
	char* rbuf2, *rbuf = new char[rlen];

	Base64Converter dec(conn, a ? a->CheckString() : "");
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

BroString* encode_base64(const BroString* s, const BroString* a, Connection* conn)
	{
	if ( a && a->Len() != 0 && a->Len() != 64 )
		{
		reporter->Error("base64 alphabet is not 64 characters: %s",
		                a->CheckString());
		return 0;
		}

	char* outbuf = 0;
	int outlen = 0;
	Base64Converter enc(conn, a ? a->CheckString() : "");
	enc.Encode(s->Len(), (const unsigned char*) s->Bytes(), &outlen, &outbuf);

	return new BroString(1, (u_char*)outbuf, outlen);
	}

