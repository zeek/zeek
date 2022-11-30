// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/script_opt/CPP/Tracker.h"

#include "zeek/Desc.h"
#include "zeek/script_opt/CPP/Util.h"
#include "zeek/script_opt/ProfileFunc.h"

namespace zeek::detail
	{

using namespace std;

template <class T> void CPPTracker<T>::AddKey(IntrusivePtr<T> key, p_hash_type h)
	{
	if ( HasKey(key) )
		return;

	if ( map2.count(h) == 0 )
		{
		auto index = keys.size();
		keys.push_back(key);

		map2[h] = index;
		reps[h] = key.get();
		}

	ASSERT(h != 0); // check for hash botches

	map[key.get()] = h;
	}

template <class T> string CPPTracker<T>::KeyName(const T* key)
	{
	ASSERT(HasKey(key));

	auto hash = map[key];
	ASSERT(hash != 0);

	auto rep = reps[hash];
	auto gi = gi_s.find(rep);
	if ( gi != gi_s.end() )
		return gi->second->Name();

	auto index = map2[hash];
	string ind = Fmt(index);
	string full_name;

	if ( single_global )
		full_name = base_name + "__CPP[" + ind + "]";
	else
		full_name = base_name + "_" + ind + "__CPP";

	return full_name;
	}

// Instantiate the templates we'll need.
template class CPPTracker<Type>;
template class CPPTracker<Attributes>;
template class CPPTracker<Expr>;

	} // zeek::detail
