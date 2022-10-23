// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/script_opt/CPP/RuntimeOps.h"

#include "zeek/EventRegistry.h"
#include "zeek/Frame.h"
#include "zeek/IPAddr.h"
#include "zeek/RunState.h"
#include "zeek/Trigger.h"
#include "zeek/ZeekString.h"

namespace zeek::detail
	{

using namespace std;

StringValPtr str_concat__CPP(const String* s1, const String* s2)
	{
	vector<const String*> strings(2);
	strings[0] = s1;
	strings[1] = s2;

	return make_intrusive<StringVal>(concatenate(strings));
	}

bool str_in__CPP(const String* s1, const String* s2)
	{
	auto s = reinterpret_cast<const unsigned char*>(s1->CheckString());
	return util::strstr_n(s2->Len(), s2->Bytes(), s1->Len(), s) != -1;
	}

ListValPtr index_val__CPP(vector<ValPtr> indices)
	{
	auto ind_v = make_intrusive<ListVal>(TYPE_ANY);

	// In the future, we could provide N versions of this that
	// unroll the loop.
	for ( const auto& i : indices )
		ind_v->Append(i);

	return ind_v;
	}

ValPtr index_table__CPP(const TableValPtr& t, vector<ValPtr> indices)
	{
	auto v = t->FindOrDefault(index_val__CPP(move(indices)));
	if ( ! v )
		reporter->CPPRuntimeError("no such index");
	return v;
	}

ValPtr index_vec__CPP(const VectorValPtr& vec, int index)
	{
	auto v = vec->ValAt(index);
	if ( ! v )
		reporter->CPPRuntimeError("no such index");
	return v;
	}

ValPtr index_string__CPP(const StringValPtr& svp, vector<ValPtr> indices)
	{
	return index_string(svp->AsString(), index_val__CPP(move(indices)).get());
	}

ValPtr when_index_table__CPP(const TableValPtr& t, vector<ValPtr> indices)
	{
	auto v = index_table__CPP(t, std::move(indices));
	if ( v && IndexExprWhen::evaluating > 0 )
		IndexExprWhen::results.emplace_back(v);
	return v;
	}

ValPtr when_index_vec__CPP(const VectorValPtr& vec, int index)
	{
	auto v = index_vec__CPP(vec, index);
	if ( v && IndexExprWhen::evaluating > 0 )
		IndexExprWhen::results.emplace_back(v);
	return v;
	}

ValPtr when_index_slice__CPP(VectorVal* vec, const ListVal* lv)
	{
	auto v = index_slice(vec, lv);
	if ( v && IndexExprWhen::evaluating > 0 )
		IndexExprWhen::results.emplace_back(v);
	return v;
	}

ValPtr when_invoke__CPP(Func* f, std::vector<ValPtr> args, Frame* frame, void* caller_addr)
	{
	auto trigger = frame->GetTrigger();

	if ( trigger )
		{
		Val* v = trigger->Lookup(caller_addr);
		if ( v )
			return {NewRef{}, v};
		}

	frame->SetTriggerAssoc(caller_addr);

	auto res = f->Invoke(&args, frame);
	if ( ! res )
		throw DelayedCallException();

	return res;
	}

ValPtr set_event__CPP(IDPtr g, ValPtr v, EventHandlerPtr& gh)
	{
	g->SetVal(v);
	gh = event_registry->Register(g->Name());
	return v;
	}

ValPtr cast_value_to_type__CPP(const ValPtr& v, const TypePtr& t)
	{
	auto result = cast_value_to_type(v.get(), t.get());
	if ( ! result )
		reporter->CPPRuntimeError("invalid cast of value with type '%s' to type '%s'",
		                          type_name(v->GetType()->Tag()), type_name(t->Tag()));
	return result;
	}

ValPtr from_any__CPP(const ValPtr& v, const TypePtr& t)
	{
	auto vt = v->GetType()->Tag();

	if ( vt != t->Tag() && vt != TYPE_ERROR )
		reporter->CPPRuntimeError("incompatible \"any\" type (%s vs. %s)", type_name(vt),
		                          type_name(t->Tag()));

	return v;
	}

ValPtr from_any_vec__CPP(const ValPtr& v, const TypePtr& t)
	{
	if ( ! v->AsVectorVal()->Concretize(t) )
		reporter->CPPRuntimeError("incompatible \"vector of any\" type");

	return v;
	}

SubNetValPtr addr_mask__CPP(const IPAddr& a, uint32_t mask)
	{
	if ( a.GetFamily() == IPv4 )
		{
		if ( mask > 32 )
			reporter->CPPRuntimeError("bad IPv4 subnet prefix length: %d", int(mask));
		}
	else
		{
		if ( mask > 128 )
			reporter->CPPRuntimeError("bad IPv6 subnet prefix length: %d", int(mask));
		}

	return make_intrusive<SubNetVal>(a, mask);
	}

// Helper function for reporting invalidation of interators.
static void check_iterators__CPP(bool invalid)
	{
	if ( invalid )
		reporter->Warning("possible loop/iterator invalidation in compiled code");
	}

// Template for aggregate assignments of the form "v1[v2] = v3".
template <typename T> ValPtr assign_to_index__CPP(T v1, ValPtr v2, ValPtr v3)
	{
	bool iterators_invalidated = false;
	auto err_msg = assign_to_index(move(v1), move(v2), v3, iterators_invalidated);

	check_iterators__CPP(iterators_invalidated);

	if ( err_msg )
		reporter->CPPRuntimeError("%s", err_msg);

	return v3;
	}

ValPtr assign_to_index__CPP(TableValPtr v1, ValPtr v2, ValPtr v3)
	{
	return assign_to_index__CPP<TableValPtr>(move(v1), move(v2), move(v3));
	}
ValPtr assign_to_index__CPP(VectorValPtr v1, ValPtr v2, ValPtr v3)
	{
	return assign_to_index__CPP<VectorValPtr>(move(v1), move(v2), move(v3));
	}
ValPtr assign_to_index__CPP(StringValPtr v1, ValPtr v2, ValPtr v3)
	{
	return assign_to_index__CPP<StringValPtr>(move(v1), move(v2), move(v3));
	}

void add_element__CPP(TableValPtr aggr, ListValPtr indices)
	{
	bool iterators_invalidated = false;
	aggr->Assign(indices, nullptr, true, &iterators_invalidated);
	check_iterators__CPP(iterators_invalidated);
	}

void remove_element__CPP(TableValPtr aggr, ListValPtr indices)
	{
	bool iterators_invalidated = false;
	aggr->Remove(*indices.get(), true, &iterators_invalidated);
	check_iterators__CPP(iterators_invalidated);
	}

// A helper function that takes a parallel vectors of attribute tags
// and values and returns a collective AttributesPtr corresponding to
// those instantiated attributes.  For attributes that don't have
// associated expressions, the corresponding value should be nil.
static AttributesPtr build_attrs__CPP(vector<int> attr_tags, vector<ValPtr> attr_vals)
	{
	vector<AttrPtr> attrs;
	int nattrs = attr_tags.size();
	for ( auto i = 0; i < nattrs; ++i )
		{
		auto t_i = AttrTag(attr_tags[i]);
		const auto& v_i = attr_vals[i];
		ExprPtr e;

		if ( v_i )
			e = make_intrusive<ConstExpr>(v_i);

		attrs.emplace_back(make_intrusive<Attr>(t_i, e));
		}

	return make_intrusive<Attributes>(move(attrs), nullptr, false, false);
	}

TableValPtr set_constructor__CPP(vector<ValPtr> elements, TableTypePtr t, vector<int> attr_tags,
                                 vector<ValPtr> attr_vals)
	{
	auto attrs = build_attrs__CPP(move(attr_tags), move(attr_vals));
	auto aggr = make_intrusive<TableVal>(move(t), move(attrs));

	for ( auto& elem : elements )
		aggr->Assign(move(elem), nullptr);

	return aggr;
	}

TableValPtr table_constructor__CPP(vector<ValPtr> indices, vector<ValPtr> vals, TableTypePtr t,
                                   vector<int> attr_tags, vector<ValPtr> attr_vals)
	{
	const auto& yt = t->Yield();
	auto n = indices.size();

	auto attrs = build_attrs__CPP(move(attr_tags), move(attr_vals));
	auto aggr = make_intrusive<TableVal>(move(t), move(attrs));

	for ( auto i = 0u; i < n; ++i )
		{
		auto v = check_and_promote(vals[i], yt, true);
		if ( v )
			aggr->Assign(move(indices[i]), move(v));
		}

	return aggr;
	}

void assign_attrs__CPP(IDPtr id, std::vector<int> attr_tags, std::vector<ValPtr> attr_vals)
	{
	id->SetAttrs(build_attrs__CPP(move(attr_tags), move(attr_vals)));
	}

RecordValPtr record_constructor__CPP(vector<ValPtr> vals, RecordTypePtr t)
	{
	auto rv = make_intrusive<RecordVal>(t);
	auto n = vals.size();

	for ( auto i = 0u; i < n; ++i )
		{
		auto& v_i = vals[i];

		if ( v_i && v_i->GetType()->Tag() == TYPE_VECTOR && v_i->AsVectorVal()->Size() == 0 )
			{
			const auto& t_ind = t->GetFieldType(i);
			v_i->AsVectorVal()->Concretize(t_ind->Yield());
			}

		rv->Assign(i, v_i);
		}

	return rv;
	}

RecordValPtr record_constructor_map__CPP(vector<ValPtr> vals, vector<int> map, RecordTypePtr t)
	{
	auto rv = make_intrusive<RecordVal>(t);
	auto n = vals.size();

	for ( auto i = 0u; i < n; ++i )
		{
		auto& v_i = vals[i];
		auto ind = map[i];

		if ( v_i && v_i->GetType()->Tag() == TYPE_VECTOR && v_i->AsVectorVal()->Size() == 0 )
			{
			const auto& t_ind = t->GetFieldType(ind);
			v_i->AsVectorVal()->Concretize(t_ind->Yield());
			}

		rv->Assign(ind, v_i);
		}

	return rv;
	}

VectorValPtr vector_constructor__CPP(vector<ValPtr> vals, VectorTypePtr t)
	{
	auto vv = make_intrusive<VectorVal>(move(t));
	auto n = vals.size();

	for ( auto i = 0u; i < n; ++i )
		vv->Assign(i, vals[i]);

	return vv;
	}

ValPtr schedule__CPP(double dt, EventHandlerPtr event, vector<ValPtr> args)
	{
	if ( ! run_state::terminating )
		timer_mgr->Add(new ScheduleTimer(event, move(args), dt));

	return nullptr;
	}

	} // namespace zeek::detail
