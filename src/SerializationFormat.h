// $Id: SerializationFormat.h 5873 2008-06-28 19:25:03Z vern $
//
// Implements different data formats for serialization.

#ifndef SERIALIZATION_FORMAT
#define SERIALIZATION_FORMAT

#include "util.h"

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

	// Passes ownership of string.
	virtual bool Read(char** str, int* len, const char* tag) = 0;

	// Serialization.
	virtual void StartWrite();
	virtual uint32 EndWrite(char** data);	// passes ownership

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

	virtual bool WriteOpenTag(const char* tag) = 0;
	virtual bool WriteCloseTag(const char* tag) = 0;
	virtual bool WriteSeparator() = 0;

	// Returns number of raw bytes written since last call to StartWrite().
	int BytesWritten() const	{ return bytes_written; }

protected:
	bool ReadData(void* buf, size_t count);
	bool WriteData(const void* buf, size_t count);

	static const uint32 INITIAL_SIZE = 65536;
	char* output;
	uint32 output_size;
	uint32 output_pos;

	char* input;
	uint32 input_len;
	uint32 input_pos;

	int bytes_written;
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

private:
	// Encodes non-printable characters.
	bool WriteEncodedString(const char* str, int len);

	// Write an elment including type and encoding.
	bool WriteElem(const char* tag, const char* type,
				   const char* content, int len);
};

#endif
