#include "zeek/session/SessionKey.h"

#include <cstring>

namespace zeek::session::detail {

SessionKey::SessionKey(const void* session, size_t size, bool copy) : size(size)
	{
	data = reinterpret_cast<const uint8_t*>(session);
	if ( copy )
		CopyData();
	}

SessionKey::SessionKey(SessionKey&& rhs)
	{
	data = rhs.data;
	size = rhs.size;
	copied = rhs.copied;

	rhs.data = nullptr;
	rhs.size = 0;
	rhs.copied = false;
	}

SessionKey& SessionKey::operator=(SessionKey&& rhs)
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

SessionKey::~SessionKey()
	{
	if ( copied )
		delete [] data;
	}

void SessionKey::CopyData()
	{
	if ( copied )
		return;

	copied = true;

	uint8_t *temp = new uint8_t[size];
	memcpy(temp, data, size);
	data = temp;
	}

bool SessionKey::operator<(const SessionKey& rhs) const
	{
	if ( size != rhs.size )
		return size < rhs.size;

	return memcmp(data, rhs.data, size) < 0;
	}

} // namespace zeek::session::detail
