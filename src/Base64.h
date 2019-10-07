#ifndef base64_h
#define base64_h

#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "util.h"
#include "BroString.h"
#include "Reporter.h"
#include "Conn.h"

// Maybe we should have a base class for generic decoders?
class Base64Converter {
public:
	// <conn> is used for error reporting. If it is set to zero (as,
	// e.g., done by the built-in functions decode_base64() and
	// encode_base64()), encoding-errors will go to Reporter instead of
	// Weird. Usage errors go to Reporter in any case. Empty alphabet
	// indicates the default base64 alphabet.
	explicit Base64Converter(Connection* conn, const string& alphabet = "");
	~Base64Converter();

	// A note on Decode():
	//
	// The input is specified by <len> and <data> and the output
	// buffer by <blen> and <buf>.  If *buf is nil, a buffer of
	// an appropriate size will be new'd and *buf will point
	// to the buffer on return. *blen holds the length of
	// decoded data on return.  The function returns the number of
	// input bytes processed, since the decoding will stop when there
	// is not enough output buffer space.

	size_t Decode(size_t len, const char* data, size_t* pblen, char** buf);
	void Encode(size_t len, const unsigned char* data, size_t* blen, char** buf);

	int Done(size_t* pblen, char** pbuf);
	int HasData() const { return base64_group_next != 0; }

	// True if an error has occurred.
	int Errored() const	{ return errored; }

	const char* ErrorMsg() const	{ return error_msg; }
	void IllegalEncoding(const char* msg)
		{
		// strncpy(error_msg, msg, sizeof(error_msg));
		if ( conn )
			conn->Weird("base64_illegal_encoding", msg);
		else
			reporter->Error("%s", msg);
		}

protected:
	char error_msg[256];

protected:
	static const string default_alphabet;
	string alphabet;

	static int* InitBase64Table(const string& alphabet);
	static int default_base64_table[256];
	char base64_group[4];
	int base64_group_next;
	int base64_padding;
	int base64_after_padding;
	int* base64_table;
	int errored;	// if true, we encountered an error - skip further processing
	Connection* conn;

};

BroString* decode_base64(const BroString* s, const BroString* a = 0, Connection* conn = 0);
BroString* encode_base64(const BroString* s, const BroString* a = 0, Connection* conn = 0);

#endif /* base64_h */
