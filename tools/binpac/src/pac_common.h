#ifndef pac_common_h
#define pac_common_h

#include "pac_utils.h"

#include <vector>

#include <ctype.h>
#include <string.h>
#include <stdlib.h>

using namespace std;

extern bool FLAGS_pac_debug;
extern bool FLAGS_quiet;
extern vector<string> FLAGS_include_directories;
extern string input_filename;
extern int line_number;

// Definition of class Object, which is the base class for all objects
// representing language elements -- identifiers, types, expressions,
// etc.

class Object
{
public:
	Object()
		{
		filename = input_filename;
		line_num = line_number;
		location = strfmt("%s:%d", filename.c_str(), line_number);
		}

	~Object()
		{
		}

	const char* Location() const	{ return location.c_str(); }

protected:
	string filename;
	int line_num;
	string location;
};

class ActionParam;
class ActionParamType;
class AnalyzerAction;
class AnalyzerContextDecl;
class AnalyzerDecl;
class AnalyzerElement;
class ArrayType;
class Attr;
class CClass;
class CType;
class ConstString;
class CaseExpr;
class CaseField;
class ContextField;
class DataPtr;
class Decl;
class EmbeddedCode;
class Enum;
class Env;
class ExternType;
class Expr;
class Field;
class Function;
class InputBuffer;
class LetDef;
class LetField;
class ID;
class Number;
class Output;
class PacPrimitive;
class Param;
class ParameterizedType;
class RecordType;
class RecordField;
class RecordDataField;
class RecordPaddingField;
class RegEx;
class SeqEnd;
class StateVar;
class Type;
class TypeDecl;
class WithInputField;

// The ID of the current declaration.
extern const ID* current_decl_id;

typedef vector<ActionParam*>		ActionParamList;
typedef vector<AnalyzerAction*> 	AnalyzerActionList;
typedef vector<AnalyzerElement*>	AnalyzerElementList;
typedef vector<Attr*> 			AttrList;
typedef vector<CaseExpr*> 		CaseExprList;
typedef vector<CaseField*> 		CaseFieldList;
typedef vector<ContextField*> 		ContextFieldList;
typedef vector<Decl*> 			DeclList;
typedef vector<Enum*>			EnumList;
typedef vector<Expr*> 			ExprList;
typedef vector<Field*> 			FieldList;
typedef vector<LetField*> 		LetFieldList;
typedef vector<Number*>			NumList;
typedef vector<Param*> 			ParamList;
typedef vector<RecordField*> 		RecordFieldList;
typedef vector<StateVar*>		StateVarList;

#define foreach(i, ct, pc) \
	if ( pc ) \
		for ( ct::iterator i = (pc)->begin(); i != (pc)->end(); ++i )

#define delete_list(ct, pc) \
	{ \
	foreach(delete_list_i, ct, pc) 		\
		delete *delete_list_i;		\
	delete pc;				\
	pc = 0;					\
	}

// Constants
const char * const kComputeFrameLength = "compute_frame_length";
const char * const kFlowBufferClass = "FlowBuffer";
const char * const kFlowBufferVar = "flow_buffer";
const char * const kFlowEOF = "FlowEOF";
const char * const kFlowGap = "NewGap";
const char * const kInitialBufferLengthFunc = "initial_buffer_length";
const char * const kNeedMoreData = "need_more_data";
const char * const kNewData = "NewData";
const char * const kParseFuncWithBuffer = "ParseBuffer";
const char * const kParseFuncWithoutBuffer = "Parse";
const char * const kRefCountClass = "binpac::RefCount";
const char * const kTypeWithLengthClass = "binpac::TypeWithLength";

#endif  // pac_common_h
