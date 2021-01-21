#pragma once

#include "zeek-config.h"
#include <string>

namespace zeek { class String; }
ZEEK_FORWARD_DECLARE_NAMESPACED(Connection, zeek);

namespace zeek::detail {

// Maybe we should have a base class for generic decoders?
class Base64Converter {
public:
	// <conn> is used for error reporting. If it is set to zero (as,
	// e.g., done by the built-in functions decode_base64() and
	// encode_base64()), encoding-errors will go to Reporter instead of
	// Weird. Usage errors go to Reporter in any case. Empty alphabet
	// indicates the default base64 alphabet.
	explicit Base64Converter(Connection* conn, const std::string& alphabet = "");
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

	int Decode(int len, const char* data, int* blen, char** buf);
	void Encode(int len, const unsigned char* data, int* blen, char** buf);

	int Done(int* pblen, char** pbuf);
	bool HasData() const { return base64_group_next != 0; }

	// True if an error has occurred.
	int Errored() const	{ return errored; }

	const char* ErrorMsg() const	{ return error_msg; }
	void IllegalEncoding(const char* msg);

protected:
	char error_msg[256];

protected:
	static const std::string default_alphabet;
	std::string alphabet;

	static int* InitBase64Table(const std::string& alphabet);
	static int default_base64_table[256];
	char base64_group[4];
	int base64_group_next;
	int base64_padding;
	int base64_after_padding;
	int* base64_table;
	int errored;	// if true, we encountered an error - skip further processing
	Connection* conn;

};

String* decode_base64(const String* s, const String* a = nullptr, Connection* conn = nullptr);
String* encode_base64(const String* s, const String* a = nullptr, Connection* conn = nullptr);

} // namespace zeek::detail
