#include "pac_btype.h"
#include "pac_dataptr.h"
#include "pac_id.h"
#include "pac_output.h"

Type *BuiltInType::DoClone() const
	{
	return new BuiltInType(bit_type());
	}

bool BuiltInType::IsNumericType() const
	{
	BITType t = bit_type();
	return (t == INT8 || t == INT16 || t == INT32 || t == INT64 || 
	        t == UINT8 || t == UINT16 || t == UINT32 || t == UINT64);
	}

bool BuiltInType::CompatibleBuiltInTypes(BuiltInType *type1, 
	                                 BuiltInType *type2)
	{
	return type1->IsNumericType() && type2->IsNumericType();
	}

static const char* basic_pactype_name[] = {
#	define TYPE_DEF(name, pactype, ctype, size)	pactype,
#	include "pac_type.def"
#	undef TYPE_DEF
	0,
};

void BuiltInType::static_init()
	{
	for ( int bit_type = 0; basic_pactype_name[bit_type]; ++bit_type )
		{
		Type::AddPredefinedType(
			basic_pactype_name[bit_type], 
			new BuiltInType((BITType) bit_type));
		}
	}

int BuiltInType::LookUpByName(const char* name)
	{
	ASSERT(0);
	for ( int i = 0; basic_pactype_name[i]; ++i )
		if ( strcmp(basic_pactype_name[i], name) == 0 )
			return i;
	return -1;
	}

static const char* basic_ctype_name[] = {
#	define TYPE_DEF(name, pactype, ctype, size)	ctype,
#	include "pac_type.def"
#	undef TYPE_DEF
	0,
};

bool BuiltInType::DefineValueVar() const
	{
	return bit_type_ != EMPTY;
	}

string BuiltInType::DataTypeStr() const
	{
	return basic_ctype_name[bit_type_];
	}

int BuiltInType::StaticSize(Env* /* env */) const
	{
	static const size_t basic_type_size[] = 
		{
#		define TYPE_DEF(name, pactype, ctype, size)	size,
#		include "pac_type.def"
#		undef TYPE_DEF
		};

	return basic_type_size[bit_type_];
	}

void BuiltInType::DoMarkIncrementalInput()
	{
	if ( bit_type_ == EMPTY )
		return;
	Type::DoMarkIncrementalInput();
	}

void BuiltInType::GenInitCode(Output* out_cc, Env* env)
	{
	if ( bit_type_ != EMPTY )
		out_cc->println("%s = 0;", env->LValue(value_var()));
	Type::GenInitCode(out_cc, env);
	}

void BuiltInType::GenDynamicSize(Output* out_cc, Env* env, const DataPtr& data)
	{
	/* should never be called */
	ASSERT(0);
	}

void BuiltInType::DoGenParseCode(Output* out_cc, Env* env,
		const DataPtr& data, int flags)
	{
	if ( bit_type_ == EMPTY )
		return;

	// There is no need to generate the size variable
	// out_cc->println("%s = sizeof(%s);", size_var(), DataTypeStr().c_str());

	GenBoundaryCheck(out_cc, env, data);

	if ( anonymous_value_var() )
		return;

	switch ( bit_type_ ) 
		{
		case EMPTY:
			// do nothing
			break;

		case INT8:
		case UINT8:
			out_cc->println("%s = *((%s const *) (%s));",
				lvalue(), DataTypeStr().c_str(), data.ptr_expr()); 
			break;
		case INT16:
		case UINT16:
		case INT32:
		case UINT32:
		case INT64:
		case UINT64:
#if 0
			out_cc->println("%s = UnMarshall<%s>(%s, %s);",
				lvalue(), 
				DataTypeStr().c_str(), 
				data.ptr_expr(),
				EvalByteOrder(out_cc, env).c_str());
#else
			out_cc->println("%s = FixByteOrder(%s, *((%s const *) (%s)));",
				lvalue(), 
				EvalByteOrder(out_cc, env).c_str(),
				DataTypeStr().c_str(), 
				data.ptr_expr());
#endif
			break;
		}
	}

