// Implements different data formats for serialization.

#ifndef SERIALIZATION_FORMAT
#define SERIALIZATION_FORMAT

#include <string>

using namespace std;

#include "util.h"

class IPAddr;
class IPPrefix;

// Abstract base class.
class SerializationFormat {
public:
	SerializationFormat();
	virtual ~SerializationFormat();

	// Unserialization.
	virtual void StartRead(char* data, uint32 len);
	virtual void EndRead();

	virtual bool Read(int* v, const char* tag) = 0;
	virtual bool Read(uint16* v, const char* tag) = 0;
	virtual bool Read(uint32* v, const char* tag) = 0;
	virtual bool Read(int64* v, const char* tag) = 0;
	virtual bool Read(uint64* v, const char* tag) = 0;
	virtual bool Read(char* v, const char* tag) = 0;
	virtual bool Read(bool* v, const char* tag) = 0;
	virtual bool Read(double* d, const char* tag) = 0;
	virtual bool Read(string* s, const char* tag) = 0;
	virtual bool Read(IPAddr* addr, const char* tag) = 0;
	virtual bool Read(IPPrefix* prefix, const char* tag) = 0;
	virtual bool Read(struct in_addr* addr, const char* tag) = 0;
	virtual bool Read(struct in6_addr* addr, const char* tag) = 0;

	// Returns number of raw bytes read since last call to StartRead().
	int BytesRead() const	{ return bytes_read; }

	// Passes ownership of string.
	virtual bool Read(char** str, int* len, const char* tag) = 0;

	// Serialization.
	virtual void StartWrite();

	/**
	 * Retrieves serialized data.
	 * @param data A pointer that will be assigned to point at the internal
	 *             buffer containing serialized data.  The memory should
	 *             be reclaimed using "free()".
	 * @return The number of bytes in the buffer object assigned to \a data.
	 */
	virtual uint32 EndWrite(char** data);

	virtual bool Write(int v, const char* tag) = 0;
	virtual bool Write(uint16 v, const char* tag) = 0;
	virtual bool Write(uint32 v, const char* tag) = 0;
	virtual bool Write(int64 v, const char* tag) = 0;
	virtual bool Write(uint64 v, const char* tag) = 0;
	virtual bool Write(char v, const char* tag) = 0;
	virtual bool Write(bool v, const char* tag) = 0;
	virtual bool Write(double d, const char* tag) = 0;
	virtual bool Write(const char* s, const char* tag) = 0;
	virtual bool Write(const char* buf, int len, const char* tag) = 0;
	virtual bool Write(const string& s, const char* tag) = 0;
	virtual bool Write(const IPAddr& addr, const char* tag) = 0;
	virtual bool Write(const IPPrefix& prefix, const char* tag) = 0;
	virtual bool Write(const struct in_addr& addr, const char* tag) = 0;
	virtual bool Write(const struct in6_addr& addr, const char* tag) = 0;

	virtual bool WriteOpenTag(const char* tag) = 0;
	virtual bool WriteCloseTag(const char* tag) = 0;
	virtual bool WriteSeparator() = 0;

	// Returns number of raw bytes written since last call to StartWrite().
	int BytesWritten() const	{ return bytes_written; }

protected:
	bool ReadData(void* buf, size_t count);
	bool WriteData(const void* buf, size_t count);

	static const uint32 INITIAL_SIZE = 65536;
	static const float GROWTH_FACTOR;
	char* output;
	uint32 output_size;
	uint32 output_pos;

	char* input;
	uint32 input_len;
	uint32 input_pos;

	int bytes_written;
	int bytes_read;
};

class BinarySerializationFormat : public SerializationFormat {
public:
	BinarySerializationFormat();
	virtual ~BinarySerializationFormat();

	virtual bool Read(int* v, const char* tag);
	virtual bool Read(uint16* v, const char* tag);
	virtual bool Read(uint32* v, const char* tag);
	virtual bool Read(int64* v, const char* tag);
	virtual bool Read(uint64* v, const char* tag);
	virtual bool Read(char* v, const char* tag);
	virtual bool Read(bool* v, const char* tag);
	virtual bool Read(double* d, const char* tag);
	virtual bool Read(char** str, int* len, const char* tag);
	virtual bool Read(string* s, const char* tag);
	virtual bool Read(IPAddr* addr, const char* tag);
	virtual bool Read(IPPrefix* prefix, const char* tag);
	virtual bool Read(struct in_addr* addr, const char* tag);
	virtual bool Read(struct in6_addr* addr, const char* tag);
	virtual bool Write(int v, const char* tag);
	virtual bool Write(uint16 v, const char* tag);
	virtual bool Write(uint32 v, const char* tag);
	virtual bool Write(int64 v, const char* tag);
	virtual bool Write(uint64 v, const char* tag);
	virtual bool Write(char v, const char* tag);
	virtual bool Write(bool v, const char* tag);
	virtual bool Write(double d, const char* tag);
	virtual bool Write(const char* s, const char* tag);
	virtual bool Write(const char* buf, int len, const char* tag);
	virtual bool Write(const string& s, const char* tag);
	virtual bool Write(const IPAddr& addr, const char* tag);
	virtual bool Write(const IPPrefix& prefix, const char* tag);
	virtual bool Write(const struct in_addr& addr, const char* tag);
	virtual bool Write(const struct in6_addr& addr, const char* tag);
	virtual bool WriteOpenTag(const char* tag);
	virtual bool WriteCloseTag(const char* tag);
	virtual bool WriteSeparator();
};

class XMLSerializationFormat:public SerializationFormat {
public:
	XMLSerializationFormat();
	virtual ~ XMLSerializationFormat();

	// We don't write anything if tag is nil.
	virtual bool Write(int v, const char* tag);
	virtual bool Write(uint16 v, const char* tag);
	virtual bool Write(uint32 v, const char* tag);
	virtual bool Write(int64 v, const char* tag);
	virtual bool Write(uint64 v, const char* tag);
	virtual bool Write(char v, const char* tag);
	virtual bool Write(bool v, const char* tag);
	virtual bool Write(double d, const char* tag);
	virtual bool Write(const char* s, const char* tag);
	virtual bool Write(const char* buf, int len, const char* tag);
	virtual bool Write(const string& s, const char* tag);
	virtual bool Write(const IPAddr& addr, const char* tag);
	virtual bool Write(const IPPrefix& prefix, const char* tag);
	virtual bool Write(const struct in_addr& addr, const char* tag);
	virtual bool Write(const struct in6_addr& addr, const char* tag);
	virtual bool WriteOpenTag(const char* tag);
	virtual bool WriteCloseTag(const char* tag);
	virtual bool WriteSeparator();

	// Not implemented.
	virtual bool Read(int* v, const char* tag);
	virtual bool Read(uint16* v, const char* tag);
	virtual bool Read(uint32* v, const char* tag);
	virtual bool Read(int64* v, const char* tag);
	virtual bool Read(uint64* v, const char* tag);
	virtual bool Read(char* v, const char* tag);
	virtual bool Read(bool* v, const char* tag);
	virtual bool Read(double* d, const char* tag);
	virtual bool Read(char** str, int* len, const char* tag);
	virtual bool Read(string* s, const char* tag);
	virtual bool Read(IPAddr* addr, const char* tag);
	virtual bool Read(IPPrefix* prefix, const char* tag);
	virtual bool Read(struct in_addr* addr, const char* tag);
	virtual bool Read(struct in6_addr* addr, const char* tag);

private:
	// Encodes non-printable characters.
	bool WriteEncodedString(const char* str, int len);

	// Write an elment including type and encoding.
	bool WriteElem(const char* tag, const char* type,
				   const char* content, int len);
};

#endif
