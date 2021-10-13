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

	if ( h == 0 )
		h = Hash(key);

	if ( map2.count(h) == 0 )
		{
		int index;
		if ( mapper && mapper->count(h) > 0 )
			{
			const auto& pair = (*mapper)[h];
			index = pair.index;
			scope2[h] = Fmt(pair.scope);
			inherited.insert(h);
			}
		else
			{
			index = num_non_inherited++;
			keys.push_back(key);
			}

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

	auto index = map2[hash];

	string scope;
	if ( IsInherited(hash) )
		scope = scope_prefix(scope2[hash]);

	return scope + string(base_name) + "_" + Fmt(index) + "__CPP";
	}

template <class T> void CPPTracker<T>::LogIfNew(IntrusivePtr<T> key, int scope, FILE* log_file)
	{
	if ( IsInherited(key) )
		return;

	auto hash = map[key.get()];
	auto index = map2[hash];

	fprintf(log_file, "hash\n%llu %d %d\n", hash, index, scope);
	}

template <class T> p_hash_type CPPTracker<T>::Hash(IntrusivePtr<T> key) const
	{
	ODesc d;
	d.SetDeterminism(true);
	key->Describe(&d);
	string desc = d.Description();
	auto h = hash<string>{}(base_name + desc);
	return p_hash_type(h);
	}

// Instantiate the templates we'll need.
template class CPPTracker<Type>;
template class CPPTracker<Attributes>;
template class CPPTracker<Expr>;

	} // zeek::detail
