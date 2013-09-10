#include "pac_attr.h"
#include "pac_common.h"
#include "pac_exception.h"
#include "pac_field.h"
#include "pac_id.h"
#include "pac_type.h"

Field::Field(FieldType tof, int flags, ID *id, Type *type)
	: DataDepElement(DataDepElement::FIELD),
	  tof_(tof), flags_(flags), id_(id), type_(type)
	{
	decl_id_ = current_decl_id;
	field_id_str_ = strfmt("%s:%s", decl_id()->Name(), id_->Name());
	attrs_ = 0;
	}

Field::~Field()
	{
	delete id_;
	delete type_;
	delete_list(AttrList, attrs_);
	}

void Field::AddAttr(AttrList* attrs)
	{
	bool delete_attrs = false;

	if ( ! attrs_ )
		{
		attrs_ = attrs;
		}
	else
		{
		attrs_->insert(attrs_->end(), attrs->begin(), attrs->end());
		delete_attrs = true;
		}

	foreach(i, AttrList, attrs)
		ProcessAttr(*i);

	if ( delete_attrs )
		delete attrs;
	}

void Field::ProcessAttr(Attr *a)
	{
	switch ( a->type() )
		{
		case ATTR_IF:
			if ( tof() != LET_FIELD &&
			     tof() != WITHINPUT_FIELD )
				{
				throw Exception(a, 
					"&if can only be applied to a "
					"let field");
				}
			break;
		default:
			break;
		}

	if ( type_ )
		type_->ProcessAttr(a);
	}

bool Field::anonymous_field() const
	{
	return type_ && type_->anonymous_value_var();
	}

int Field::ValueVarType() const
	{
	if ( flags_ & CLASS_MEMBER )
		return (flags_ & PUBLIC_READABLE) ? MEMBER_VAR : PRIV_MEMBER_VAR;
	else
		return TEMP_VAR;
	}

void Field::Prepare(Env *env)
	{
	if ( type_ )
		{
		if ( anonymous_field() )
			flags_ &= ~(CLASS_MEMBER | PUBLIC_READABLE);
		if ( ! type_->persistent() )
			flags_ &= (~PUBLIC_READABLE);

		type_->set_value_var(id(), ValueVarType());
		type_->Prepare(env, 
			flags_ & TYPE_TO_BE_PARSED ? 
				Type::TO_BE_PARSED : 0);
		env->SetField(id(), this);
		}
	}

void Field::GenPubDecls(Output* out_h, Env* env)
	{
	if ( type_ && (flags_ & PUBLIC_READABLE) && (flags_ & CLASS_MEMBER) )
		type_->GenPubDecls(out_h, env);
	}

void Field::GenPrivDecls(Output* out_h, Env* env)
	{
	// Generate private declaration only if it is a class member
	if ( type_ && (flags_ & CLASS_MEMBER) )
		type_->GenPrivDecls(out_h, env);
	}

void Field::GenTempDecls(Output* out_h, Env* env)
	{
	// Generate temp field
	if ( type_ && !(flags_ & CLASS_MEMBER) )
		type_->GenPrivDecls(out_h, env);
	}

void Field::GenInitCode(Output* out_cc, Env* env)
	{
	if ( type_ && ! anonymous_field() )
		type_->GenInitCode(out_cc, env);
	}

void Field::GenCleanUpCode(Output* out_cc, Env* env)
	{
	if ( type_ && ! anonymous_field() )
		type_->GenCleanUpCode(out_cc, env);
	}

bool Field::DoTraverse(DataDepVisitor *visitor)
	{
	// Check parameterized type
	if ( type_ && ! type_->Traverse(visitor) )
		return false;
	foreach(i, AttrList, attrs_)
		if ( ! (*i)->Traverse(visitor) )
			return false;
	return true;
	}

bool Field::RequiresAnalyzerContext() const
	{
	// Check parameterized type
	if ( type_ && type_->RequiresAnalyzerContext() )
		return true;
	foreach(i, AttrList, attrs_)
		if ( (*i)->RequiresAnalyzerContext() )
			return true;
	return false;
	}
