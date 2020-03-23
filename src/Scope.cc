// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek-config.h"

#include "Scope.h"
#include "Desc.h"
#include "ID.h"
#include "IntrusivePtr.h"
#include "Val.h"
#include "Reporter.h"
#include "module_util.h"

typedef PList<Scope> scope_list;

static scope_list scopes;
static Scope* top_scope;


Scope::Scope(IntrusivePtr<ID> id, attr_list* al)
	: scope_id(std::move(id))
	{
	attrs = al;
	return_type = 0;

	inits = new id_list;

	if ( id )
		{
		BroType* id_type = scope_id->Type();

		if ( id_type->Tag() == TYPE_ERROR )
			return;
		else if ( id_type->Tag() != TYPE_FUNC )
			reporter->InternalError("bad scope id");

		FuncType* ft = id->Type()->AsFuncType();
		return_type = {NewRef{}, ft->YieldType()};
		}
	}

Scope::~Scope()
	{
	if ( attrs )
		{
		for ( const auto& attr : *attrs )
			Unref(attr);

		delete attrs;
		}

	if ( inits )
		{
		for ( const auto& i : *inits )
			Unref(i);

		delete inits;
		}
	}

ID* Scope::GenerateTemporary(const char* name)
	{
	return new ID(name, SCOPE_FUNCTION, false);
	}

id_list* Scope::GetInits()
	{
	id_list* ids = inits;
	inits = 0;
	return ids;
	}

void Scope::Describe(ODesc* d) const
	{
	if ( d->IsReadable() )
		d->AddSP("scope");

	else
		{
		d->Add(scope_id != 0);
		d->SP();
		d->Add(return_type != 0);
		d->SP();
		d->Add(static_cast<uint64_t>(local.size()));
		d->SP();
		}

	if ( scope_id )
		{
		scope_id->Describe(d);
		d->NL();
		}

	if ( return_type )
		{
		return_type->Describe(d);
		d->NL();
		}

	for ( const auto& entry : local )
		{
		ID* id = entry.second.get();
		id->Describe(d);
		d->NL();
		}
	}

TraversalCode Scope::Traverse(TraversalCallback* cb) const
	{
	for ( const auto& entry : local )
		{
		ID* id = entry.second.get();
		TraversalCode tc = id->Traverse(cb);
		HANDLE_TC_STMT_PRE(tc);
		}

	return TC_CONTINUE;
	}


IntrusivePtr<ID> lookup_ID(const char* name, const char* curr_module,
                           bool no_global, bool same_module_only,
                           bool check_export)
	{
	string fullname = make_full_var_name(curr_module, name);

	string ID_module = extract_module_name(fullname.c_str());
	bool need_export = check_export && (ID_module != GLOBAL_MODULE_NAME &&
	                                    ID_module != curr_module);

	for ( int i = scopes.length() - 1; i >= 0; --i )
		{
		ID* id = scopes[i]->Lookup(fullname);
		if ( id )
			{
			if ( need_export && ! id->IsExport() && ! in_debug )
				reporter->Error("identifier is not exported: %s",
				      fullname.c_str());

			return {NewRef{}, id};
			}
		}

	if ( ! no_global && (strcmp(GLOBAL_MODULE_NAME, curr_module) == 0 ||
			     ! same_module_only) )
		{
		string globalname = make_full_var_name(GLOBAL_MODULE_NAME, name);
		ID* id = global_scope()->Lookup(globalname);
		if ( id )
			return {NewRef{}, id};
		}

	return 0;
	}

IntrusivePtr<ID> install_ID(const char* name, const char* module_name,
                            bool is_global, bool is_export)
	{
	if ( scopes.empty() && ! is_global )
		reporter->InternalError("local identifier in global scope");

	IDScope scope;
	if ( is_export || ! module_name ||
	     (is_global &&
	      normalized_module_name(module_name) == GLOBAL_MODULE_NAME) )
		scope = SCOPE_GLOBAL;
	else if ( is_global )
		scope = SCOPE_MODULE;
	else
		scope = SCOPE_FUNCTION;

	string full_name = make_full_var_name(module_name, name);

	auto id = make_intrusive<ID>(full_name.data(), scope, is_export);

	if ( SCOPE_FUNCTION != scope )
		global_scope()->Insert(std::move(full_name), id);
	else
		{
		id->SetOffset(top_scope->Length());
		top_scope->Insert(std::move(full_name), id);
		}

	return id;
	}

void push_existing_scope(Scope* scope)
	{
	scopes.push_back(scope);
	}

void push_scope(IntrusivePtr<ID> id, attr_list* attrs)
	{
	top_scope = new Scope(std::move(id), attrs);
	scopes.push_back(top_scope);
	}

IntrusivePtr<Scope> pop_scope()
	{
	if ( scopes.empty() )
		reporter->InternalError("scope underflow");
	scopes.pop_back();

	Scope* old_top = top_scope;

	top_scope = scopes.empty() ? nullptr : scopes.back();

	return {AdoptRef{}, old_top};
	}

Scope* current_scope()
	{
	return top_scope;
	}

Scope* global_scope()
	{
	return scopes.empty() ? 0 : scopes.front();
	}
