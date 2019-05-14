// Infrastructure for serializable objects.
//
// How to make objects of class Foo serializable:
//
//    1. Derive Foo (directly or indirectly) from SerialObj.
//    2. Add a SER_FOO constant to SerialTypes in SerialTypes.h.
//    3. Add DECLARE_SERIAL(Foo) into class definition.
//    4. Add a (preferably protected) default ctor if it doesn't already exist.
//    5. For non-abstract classes, add IMPLEMENT_SERIAL(Foo, SER_FOO) to *.cc
//    6. Add two methods like this to *.cc (keep names of arguments!)
//
//       bool Foo::DoSerialize(SerialInfo* info) const
//           {
//           DO_SERIALIZE(SER_FOO, ParentClassOfFoo);
//           <... serialize class members via methods in Serializer ...>
//           return true if everything ok;
//	     }
//
//       bool Foo::DoUnserialize(UnserialInfo* info)
//           {
//           DO_UNSERIALIZE(ParentClassOfFoo);
//           <... unserialize class members via methods in Serializer ...>
//           return true if everything ok;
//           }
//
//   (7. If no parent class of Foo already contains Serialize()/Unserialize()
//       methods, these need to be added somewhere too. But most of the various
//       parts of the class hierarchy already have them.)


#ifndef SERIALOBJ_H
#define SERIALOBJ_H

#include <map>
#include <util.h>

#include "DebugLogger.h"
#include "Continuation.h"
#include "SerialTypes.h"
#include "zeek-config.h"

#if SIZEOF_LONG_LONG < 8
# error "Serialization requires that sizeof(long long) is at least 8. (Remove this message only if you know what you're doing.)"
#endif

class Serializer;
class SerialInfo;
class UnserialInfo;
class SerializationCache;

// Per-process unique ID.
class TransientID {
public:
	TransientID()	{ id = ++counter; }

	typedef unsigned long long ID;
	ID Value() const	{ return id; }

private:
	ID id;
	static ID counter;
};

// Abstract base class for serializable objects.
class SerialObj {
public:
	virtual ~SerialObj()	{ }

	virtual const TransientID* GetTID() const	{ return 0; }

	virtual SerialType GetSerialType() const	{ return 0; }

	bool IsBroObj() const { return IsBroObj(GetSerialType()); }
	bool IsCacheStable() const { return IsCacheStable(GetSerialType()); }

	static const uint64 NEVER = 0;
	static const uint64 ALWAYS = 1;

	// Returns time of last modification. This "time" is a monotonically
	// increasing counter which is incremented each time a modification is
	// performed (more precisely: each time an object is modified which
	// returns something different than NEVER). Such times can thus be
	// compared to see whether some modification took place before another.
	//
	// There are two special values:
	//    NEVER:  This object will never change.
	//    ALWAYS: Always consider this object as changed, i.e., don't
	//            cache it.
	virtual uint64 LastModified() const	{ return NEVER; }

	// Instantiate an object of the given type. Return nil
	// if unknown.
	static SerialObj* Instantiate(SerialType type);

	static const char* ClassName(SerialType type);

	// Associate a "factory" function with the given type.
	// A factory is a class or function that creates instances
	// of a certain type.

	typedef SerialObj* (*FactoryFunc)();
	static void Register(SerialType type, FactoryFunc f,
			const char* class_name);

	static bool IsBroObj(SerialType type)
		{ return type & SER_IS_BRO_OBJ; }

	static bool IsCacheStable(SerialType type)
		{ return type & SER_IS_CACHE_STABLE; }

	static bool CheckTypes(SerialType type1, SerialType type2)
		{ return (type1 & SER_TYPE_MASK_PARENT) ==
			 (type2 & SER_TYPE_MASK_PARENT); }

protected:
	friend class SerializationCache;

	SerialObj()
		{
#ifdef DEBUG
		serial_type = 0;
#endif
		}

	// Serializes this object. If info->cache is false, we can use
	// DECLARE_NON_CACHEABLE_SERIAL (instead of DECLARE_SERIAL) which
	// avoids storing a per-object id.
	bool Serialize(SerialInfo* info) const;

	// Unserializes next object.
	static SerialObj* Unserialize(UnserialInfo* info,
					SerialType type);

	virtual bool DoSerialize(SerialInfo* info) const;
	virtual bool DoUnserialize(UnserialInfo* info);

	typedef std::map<SerialType, FactoryFunc> FactoryMap;
	static FactoryMap* factories;

	typedef std::map<SerialType, const char*> ClassNameMap;
	static ClassNameMap* names;

	static uint64 time_counter;
	static uint64 IncreaseTimeCounter()	{ return ++time_counter; }
	static uint64 GetTimeCounter()	{ return time_counter; }

#ifdef DEBUG
	SerialType serial_type;
#endif
};

// A class that registers a factory function upon instantiation.
class SerialTypeRegistrator {
public:
	SerialTypeRegistrator(SerialType type, SerialObj::FactoryFunc func,
			const char* class_name)
		{
		SerialObj::Register(type, func, class_name);
		}
};


// Macro helpers.

#define DECLARE_ABSTRACT_SERIAL(classname) \
	bool DoSerialize(SerialInfo*) const override; \
	bool DoUnserialize(UnserialInfo*) override; \

#define DECLARE_SERIAL(classname) \
	static classname* Instantiate(); \
	static SerialTypeRegistrator register_type; \
	bool DoSerialize(SerialInfo*) const override; \
	bool DoUnserialize(UnserialInfo*) override; \
	const TransientID*  GetTID() const override	{ return &tid; } \
	SerialType GetSerialType() const override; \
	TransientID tid;

// Only needed (and usable) for non-abstract classes.
#define IMPLEMENT_SERIAL(classname, classtype) \
	SerialTypeRegistrator classname::register_type(classtype, \
			FactoryFunc(&classname::Instantiate), #classname); \
	SerialType classname::GetSerialType() const { return classtype; }; \
	classname* classname::Instantiate()	{ return new classname(); } \

// Pushes debug level on instantiation and pops when it goes out of scope.
class AutoPush {
public:
	AutoPush()	{ DBG_PUSH(DBG_SERIAL); }
	~AutoPush()	{ DBG_POP(DBG_SERIAL); }
};

// Note that by default we disable suspending.  Use DO_SERIALIZE_WITH_SUSPEND
// to enable, but be careful to make sure that whomever calls us is aware of
// the fact (or has already disabled suspension itself).
#define DO_SERIALIZE(classtype, super) \
	DBG_LOG(DBG_SERIAL, __PRETTY_FUNCTION__); \
	if ( info->type == SER_NONE ) \
		info->type = classtype; \
	DisableSuspend suspend(info); \
	AutoPush auto_push; \
	if ( ! super::DoSerialize(info) ) \
		return false;

// Unfortunately, this is getting quite long. :-(
#define DO_SERIALIZE_WITH_SUSPEND(classtype, super) \
	DBG_LOG(DBG_SERIAL, __PRETTY_FUNCTION__); \
	if ( info->type == SER_NONE ) \
		info->type = classtype; \
	AutoPush auto_push; \
	\
	bool call_super = info->cont.NewInstance(); \
	\
	if ( info->cont.ChildSuspended() ) \
		{ \
		void* user_ptr = info->cont.RestoreState(); \
		if ( user_ptr == &call_super ) \
			call_super = true; \
		} \
	\
	if ( call_super ) \
		{ \
		info->cont.SaveState(&call_super); \
		info->cont.SaveContext(); \
		bool result = super::DoSerialize(info); \
		info->cont.RestoreContext(); \
		if ( ! result ) \
			return false; \
		if ( info->cont.ChildSuspended() ) \
			return true; \
		info->cont.SaveState(0); \
		} \

#define DO_UNSERIALIZE(super) \
	DBG_LOG(DBG_SERIAL, __PRETTY_FUNCTION__); \
	AutoPush auto_push; \
	if ( ! super::DoUnserialize(info) ) \
		return false;

#define SERIALIZE(x) \
	info->s->Write(x, #x)

#define SERIALIZE_STR(x, y) \
	info->s->Write(x, y, #x)

#define SERIALIZE_BIT(bit) \
	info->s->Write(bool(bit), #bit)

#define UNSERIALIZE(x) \
	info->s->Read(x, #x)

#define UNSERIALIZE_STR(x, y) \
	info->s->Read(x, y, #x)

#define UNSERIALIZE_BIT(bit) \
	{ \
	bool tmp; \
	if ( ! info->s->Read(&tmp, #bit) ) \
		return false; \
	bit = (unsigned int) tmp; \
	}

// Some helpers for pointers which may be nil.
#define SERIALIZE_OPTIONAL(ptr) \
	{	\
	if ( ptr )	\
		{	\
		if ( ! info->cont.ChildSuspended() )	\
			if ( ! info->s->Write(true, "has_" #ptr) )	\
				return false;	\
		\
		info->cont.SaveContext();	\
		bool result = ptr->Serialize(info);	\
		info->cont.RestoreContext();	\
		if ( ! result )	\
			return false;	\
		\
		if ( info->cont.ChildSuspended() )	\
			return true;	\
		}	\
	\
	else if ( ! info->s->Write(false, "has_" #ptr) )	\
		return false;	\
	}

#define SERIALIZE_OPTIONAL_STR(str) \
	{	\
	if ( str )	\
		{	\
		if ( ! (info->s->Write(true, "has_" #str) && info->s->Write(str, "str")) )	\
			return false;	\
		}	\
	\
	else if ( ! info->s->Write(false, "has_" #str) )	\
		return false;	\
	}

#define UNSERIALIZE_OPTIONAL(dst, unserialize)	\
	{	\
	bool has_it;	\
	if ( ! info->s->Read(&has_it, "has_" #dst) )	\
		return false;	\
	\
	if ( has_it )	\
		{	\
		dst = unserialize;	\
		if ( ! dst )	\
			return false;	\
		}	\
	\
	else	\
		dst = 0;	\
	}

#define UNSERIALIZE_OPTIONAL_STR(dst)	\
	{	\
	bool has_it;	\
	if ( ! info->s->Read(&has_it, "has_" #dst) )	\
		return false;	\
	\
	if ( has_it )	\
		{	\
		if ( ! info->s->Read(&dst, 0, "has_" #dst) )	\
			return false;	\
		if ( ! dst )	\
			return false;	\
		}	\
	\
	else	\
		dst = 0;	\
	}

#define UNSERIALIZE_OPTIONAL_STR_DEL(dst, del)	\
	{	\
	bool has_it;	\
	if ( ! info->s->Read(&has_it, "has_" #dst) )	\
		{	\
		delete del;	\
		return 0;	\
		}	\
	\
	if ( has_it )	\
		{	\
		if ( ! info->s->Read(&dst, 0, "has_" #dst) )	\
			{	\
			delete del;	\
			return 0;	\
			}	\
		if ( ! dst )	\
			{	\
			delete del;	\
			return 0;	\
			}	\
		}	\
	\
	else	\
		dst = 0;	\
	}

#define UNSERIALIZE_OPTIONAL_STATIC(dst, unserialize, del)	\
	{	\
	bool has_it;	\
	if ( ! info->s->Read(&has_it, "has_" #dst) )	\
		{	\
		delete del;	\
		return 0;	\
		}	\
	\
	if ( has_it )	\
		{	\
		dst = unserialize;	\
		if ( ! dst )	\
			{	\
			delete del;	\
			return 0;	\
			}	\
		}	\
	\
	else	\
		dst = 0;	\
	}

#endif
