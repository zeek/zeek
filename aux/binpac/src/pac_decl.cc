#include "pac_attr.h"
#include "pac_context.h"
#include "pac_dataptr.h"
#include "pac_embedded.h"
#include "pac_exception.h"
#include "pac_expr.h"
#include "pac_exttype.h"
#include "pac_id.h"
#include "pac_output.h"
#include "pac_param.h"
#include "pac_record.h"
#include "pac_type.h"
#include "pac_utils.h"

#include "pac_decl.h"

DeclList *Decl::decl_list_ = 0;
Decl::DeclMap Decl::decl_map_;

Decl::Decl(ID* id, DeclType decl_type)
	: id_(id), decl_type_(decl_type), attrlist_(0)
	{
	decl_map_[id_] = this;
	if ( ! decl_list_ )
		decl_list_ = new DeclList();
	decl_list_->push_back(this);

	DEBUG_MSG("Finished Decl %s\n", id_->Name());

	analyzer_context_ = 0;
	}

Decl::~Decl()
	{
	delete id_;
	delete_list(AttrList, attrlist_);
	}

void Decl::AddAttrs(AttrList* attrs)
	{
	if ( ! attrs )
		return;
	if ( ! attrlist_ )
		attrlist_ = new AttrList();
	foreach ( i, AttrList, attrs )
		{
		attrlist_->push_back(*i);
		ProcessAttr(*i);
		}
	}

void Decl::ProcessAttr(Attr *attr)
	{
	throw Exception(attr, "unhandled attribute");
	}

void Decl::SetAnalyzerContext()
	{
	analyzer_context_ = 
		AnalyzerContextDecl::current_analyzer_context();
	if ( ! analyzer_context_ )
		{
		throw Exception(this, 
		                "analyzer context not defined");
		}
	}

void Decl::ProcessDecls(Output *out_h, Output *out_cc)
	{
	if ( ! decl_list_ )
		return;

	foreach(i, DeclList, decl_list_)
		{
		Decl *decl = *i;
		current_decl_id = decl->id();
		decl->Prepare();
		}

	foreach(i, DeclList, decl_list_)
		{
		Decl *decl = *i;
		current_decl_id = decl->id();
		decl->GenExternDeclaration(out_h);
		}

	out_h->println("namespace binpac {\n");
	out_cc->println("namespace binpac {\n");

	AnalyzerContextDecl *analyzer_context =
		AnalyzerContextDecl::current_analyzer_context();

	foreach(i, DeclList, decl_list_)
		{
		Decl *decl = *i;
		current_decl_id = decl->id();
		decl->GenForwardDeclaration(out_h);
		}

	if ( analyzer_context )
		analyzer_context->GenNamespaceEnd(out_h);

	out_h->println("");

	foreach(i, DeclList, decl_list_)
		{
		Decl *decl = *i;
		current_decl_id = decl->id();
		decl->GenCode(out_h, out_cc);
		}

	if ( analyzer_context )
		{
		analyzer_context->GenNamespaceEnd(out_h);
		analyzer_context->GenNamespaceEnd(out_cc);
		}

	out_h->println("}  // namespace binpac");
	out_cc->println("}  // namespace binpac");
	}

Decl* Decl::LookUpDecl(const ID* id)
	{
	DeclMap::iterator it = decl_map_.find(id);
	if ( it == decl_map_.end() )
		return 0;
	return it->second;
	}

int HelperDecl::helper_id_seq = 0;

HelperDecl::HelperDecl(HelperType helper_type, 
                       ID* context_id, 
                       EmbeddedCode* code)
 	: Decl(new ID(fmt("helper_%d", ++helper_id_seq)), HELPER), 
	  helper_type_(helper_type),
	  context_id_(context_id),
	  code_(code)
	{
	}

HelperDecl::~HelperDecl()
	{
	delete context_id_;
	delete code_;
	}

void HelperDecl::Prepare()
	{
	// Do nothing
	}

void HelperDecl::GenExternDeclaration(Output *out_h)
	{
	if ( helper_type_ == EXTERN )
		code_->GenCode(out_h, global_env());
	}

void HelperDecl::GenCode(Output *out_h, Output *out_cc)
	{
	Env *env = global_env();

#if 0
	if ( context_id_ )
		{
		Decl *decl = Decl::LookUpDecl(context_id_);
		if ( ! decl )
			{
			throw Exception(context_id_, 
			                fmt("cannot find declaration for %s", 
			                    context_id_->Name()));
			}
		env = decl->env();
		if ( ! env )
			{
			throw Exception(context_id_,
			                fmt("not a type or analyzer: %s",
			                    context_id_->Name()));
			}
		}
#endif

	if ( helper_type_ == HEADER )
		code_->GenCode(out_h, env);
	else if ( helper_type_ == CODE )
		code_->GenCode(out_cc, env);
	else if ( helper_type_ == EXTERN )
		; // do nothing
	else
		ASSERT(0);
	}
