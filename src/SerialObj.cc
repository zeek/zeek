#include "SerialObj.h"
#include "Serializer.h"

TransientID::ID TransientID::counter = 0;

SerialObj::FactoryMap* SerialObj::factories = 0;
SerialObj::ClassNameMap* SerialObj::names = 0;
uint64 SerialObj::time_counter = NEVER + ALWAYS + 1;

SerialObj* SerialObj::Instantiate(SerialType type)
	{
	FactoryMap::iterator f = factories->find(type & SER_TYPE_MASK_EXACT);
	if ( f != factories->end() )
		{
		SerialObj* o = (SerialObj*) (*f->second)();
#ifdef DEBUG
		o->serial_type = o->GetSerialType();
#endif
		return o;
		}

	reporter->Error("Unknown object type 0x%08x", type);
	return 0;
	}

const char* SerialObj::ClassName(SerialType type)
	{
	ClassNameMap::iterator f = names->find(type);
	if ( f != names->end() )
		return f->second;

	reporter->Error("Unknown object type 0x%08x", type);
	return "<no-class-name>";
	}

void SerialObj::Register(SerialType type, FactoryFunc f, const char* name)
	{
	if ( ! factories )
		{
		factories = new FactoryMap;
		names = new ClassNameMap;
		}

	type = type & SER_TYPE_MASK_EXACT;

	FactoryMap::iterator i = factories->find(type);
	if ( i != factories->end() )
		reporter->InternalError("SerialType 0x%08x registered twice", type);

	(*factories)[type] = f;
	(*names)[type] = name;
	}

inline bool SerializePID(SerialInfo* info, bool full, SerializationCache::PermanentID pid)
	{
	if ( ! SERIALIZE(full) )
		return false;

	if ( ! info->pid_32bit )
		return SERIALIZE(pid);

	// Broccoli compatibility mode with 32bit pids.
	uint32 tmp = uint32(pid);
	return SERIALIZE(tmp);
	}

bool SerialObj::Serialize(SerialInfo* info) const
	{
	assert(info);

	if ( info->cont.NewInstance() )
		{
		SerializationCache::PermanentID pid = SerializationCache::NONE;

		const TransientID* tid = GetTID();

		if ( ! tid )
			reporter->InternalError("no tid - missing DECLARE_SERIAL?");

		if ( info->cache )
			pid = info->s->Cache()->Lookup(*tid);

		if ( pid != SerializationCache::NONE && info->cache )
			{
			DBG_LOG(DBG_SERIAL, "%s [%p, ref pid %lld, tid %lld]", __PRETTY_FUNCTION__, this, (long long) pid, tid->Value() );

			DBG_LOG(DBG_SERIAL, "-- Caching");
			DBG_PUSH(DBG_SERIAL);

			if ( ! SerializePID(info, false, pid) )
				{
				DBG_POP(DBG_SERIAL);
				return false;
				}

			DBG_POP(DBG_SERIAL);
			return true;
			}

		if ( info->cache )
			pid = info->s->Cache()->Register(this,
						SerializationCache::NONE,
						info->new_cache_strategy);

		DBG_LOG(DBG_SERIAL, "%s [%p, new pid %lld, tid %lld]", __PRETTY_FUNCTION__, this, (long long) pid, tid->Value() );
		DBG_LOG(DBG_SERIAL, "-- Caching");
		DBG_PUSH(DBG_SERIAL);

		if ( ! SerializePID(info, true, pid) )
			{
			DBG_POP(DBG_SERIAL);
			return false;
			}

		info->type = SER_NONE;
		DBG_POP(DBG_SERIAL);
		}

	DBG_PUSH(DBG_SERIAL);
	info->cont.SaveContext();
	bool ret = DoSerialize(info);
	info->cont.RestoreContext();
	DBG_POP(DBG_SERIAL);

	if ( info->cont.ChildSuspended() )
		return ret;

#ifdef DEBUG
	if ( debug_logger.IsEnabled(DBG_SERIAL) && IsBroObj(serial_type) )
		{
		ODesc desc(DESC_READABLE);
		((BroObj*)this)->Describe(&desc);
		DBG_LOG(DBG_SERIAL, "-- Desc: %s", desc.Description());
		}
#endif

	return ret;
	}

SerialObj* SerialObj::Unserialize(UnserialInfo* info, SerialType type)
	{
	SerializationCache::PermanentID pid = SerializationCache::NONE;

	DBG_LOG(DBG_SERIAL, "%s", __PRETTY_FUNCTION__);

	bool full_obj;

	DBG_LOG(DBG_SERIAL, "-- Caching");
	DBG_PUSH(DBG_SERIAL);

	bool result;

	if ( ! info->pid_32bit )
		result = UNSERIALIZE(&full_obj) && UNSERIALIZE(&pid);
	else
		{
		// Broccoli compatibility mode with 32bit pids.
		uint32 tmp = 0;
		result = UNSERIALIZE(&full_obj) && UNSERIALIZE(&tmp);
		pid = tmp;
		}

	if ( ! result )
		{
		DBG_POP(DBG_SERIAL);
		return 0;
		}

	DBG_POP(DBG_SERIAL);

	DBG_LOG(DBG_SERIAL, "-- [%s pid %lld]", full_obj ? "obj" : "ref", (long long) pid);

	if ( ! full_obj )
		{
		// FIXME: Yet another const_cast to check eventually...
		SerialObj* obj =
			const_cast<SerialObj*>(info->s->Cache()->Lookup(pid));
		if ( obj )
			{
			if ( obj->IsBroObj() )
				Ref((BroObj*) obj);
			return obj;
			}

		// In the following we'd like the format specifier to match
		// the type of pid; but pid is uint64, for which there's
		// no portable format specifier.  So we upcast it to long long,
		// which is at least that size, and use a matching format.
		info->s->Error(fmt("unknown object %lld referenced",
				(long long) pid));
		return 0;
		}

	uint16 stype;
	if ( ! UNSERIALIZE(&stype) )
		return 0;

	SerialObj* obj = Instantiate(SerialType(stype));

	if ( ! obj )
		{
		info->s->Error("unknown object type");
		return 0;
		}

#ifdef DEBUG
	obj->serial_type = stype;
#endif

	const TransientID* tid = obj->GetTID();
	if ( ! tid )
		reporter->InternalError("no tid - missing DECLARE_SERIAL?");

	if ( info->cache )
		info->s->Cache()->Register(obj, pid, info->new_cache_strategy);

	info->type = stype;

	DBG_PUSH(DBG_SERIAL);
	if ( ! obj->DoUnserialize(info) )
		{
		DBG_POP(DBG_SERIAL);
		return 0;
		}

	DBG_POP(DBG_SERIAL);

	if ( ! SerialObj::CheckTypes(stype, type) )
		{
		info->s->Error("type mismatch");
		return 0;
		}

#ifdef DEBUG
	if ( debug_logger.IsEnabled(DBG_SERIAL) && IsBroObj(stype) )
		{
		ODesc desc(DESC_READABLE);
		((BroObj*)obj)->Describe(&desc);
		DBG_LOG(DBG_SERIAL, "-- Desc: %s", desc.Description());
		}
#endif

	assert(obj);
	return obj;
	}

bool SerialObj::DoSerialize(SerialInfo* info) const
	{
	assert(info->type != SER_NONE);

#ifdef DEBUG
	const_cast<SerialObj*>(this)->serial_type = info->type;
#endif

	DBG_LOG(DBG_SERIAL, __PRETTY_FUNCTION__);
	DBG_PUSH(DBG_SERIAL);

	uint16 stype = uint16(info->type);

	if ( ! info->new_cache_strategy )
		{
		// This is a bit unfortunate: to make sure we're sending
		// out the same types as in the past, we need to strip out
		// the new cache stable bit.
		stype &= ~SER_IS_CACHE_STABLE;
		}

	bool ret = SERIALIZE(stype);
	DBG_POP(DBG_SERIAL);
	return ret;
	}

bool SerialObj::DoUnserialize(UnserialInfo* info)
	{
	DBG_LOG(DBG_SERIAL, __PRETTY_FUNCTION__);
	return true;
	}
