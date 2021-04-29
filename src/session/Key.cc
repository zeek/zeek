#include "zeek/session/Key.h"

#include <cstring>

namespace zeek::session::detail {

Key::Key(const void* session, size_t size, bool copy) : size(size)
	{
	data = reinterpret_cast<const uint8_t*>(session);
	if ( copy )
		CopyData();
	}

Key::Key(Key&& rhs)
	{
	data = rhs.data;
	size = rhs.size;
	copied = rhs.copied;

	rhs.data = nullptr;
	rhs.size = 0;
	rhs.copied = false;
	}

Key& Key::operator=(Key&& rhs)
	{
	if ( this != &rhs )
		{
		data = rhs.data;
		size = rhs.size;
		copied = rhs.copied;

		rhs.data = nullptr;
		rhs.size = 0;
		rhs.copied = false;
		}

	return *this;
	}

Key::~Key()
	{
	if ( copied )
		delete [] data;
	}

void Key::CopyData()
	{
	if ( copied )
		return;

	copied = true;

	uint8_t *temp = new uint8_t[size];
	memcpy(temp, data, size);
	data = temp;
	}

bool Key::operator<(const Key& rhs) const
	{
	if ( size != rhs.size )
		return size < rhs.size;

	return memcmp(data, rhs.data, size) < 0;
	}

} // namespace zeek::session::detail
