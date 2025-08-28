// See the file "COPYING" in the main distribution directory for copyright.

#ifndef pac_common_h
#define pac_common_h

#include <cctype>
#include <cstdlib>
#include <cstring>
#include <vector>

#include "pac_utils.h"

using namespace std;

extern bool FLAGS_pac_debug;
extern bool FLAGS_quiet;
extern vector<string> FLAGS_include_directories;
extern string input_filename;
extern int line_number;

// Definition of class Object, which is the base class for all objects
// representing language elements -- identifiers, types, expressions,
// etc.

class Object {
public:
    Object() {
        filename = input_filename;
        line_num = line_number;
        location = strfmt("%s:%d", filename.c_str(), line_number);
    }

    ~Object() {}

    const char* Location() const { return location.c_str(); }

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
class Nullptr;
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

using ActionParamList = vector<ActionParam*>;
using AnalyzerActionList = vector<AnalyzerAction*>;
using AnalyzerElementList = vector<AnalyzerElement*>;
using AttrList = vector<Attr*>;
using CaseExprList = vector<CaseExpr*>;
using CaseFieldList = vector<CaseField*>;
using ContextFieldList = vector<ContextField*>;
using DeclList = vector<Decl*>;
using EnumList = vector<Enum*>;
using ExprList = vector<Expr*>;
using FieldList = vector<Field*>;
using LetFieldList = vector<LetField*>;
using NumList = vector<Number*>;
using ParamList = vector<Param*>;
using RecordFieldList = vector<RecordField*>;
using StateVarList = vector<StateVar*>;

// NOLINTBEGIN(cppcoreguidelines-macro-usage,modernize-loop-convert)
#define foreach(i, ct, pc)                                                                                             \
    if ( pc )                                                                                                          \
        for ( ct::iterator i = (pc)->begin(); (i) != (pc)->end(); ++(i) )
// NOLINTEND(cppcoreguidelines-macro-usage,modernize-loop-convert)

template<typename T>
constexpr void delete_list(T* container) {
    for ( auto& i : *container )
        delete i;

    delete container;
}

// Constants
constexpr char kComputeFrameLength[] = "compute_frame_length";
constexpr char kFlowBufferClass[] = "FlowBuffer";
constexpr char kFlowBufferVar[] = "flow_buffer";
constexpr char kFlowEOF[] = "FlowEOF";
constexpr char kFlowGap[] = "NewGap";
constexpr char kInitialBufferLengthFunc[] = "initial_buffer_length";
constexpr char kNeedMoreData[] = "need_more_data";
constexpr char kNewData[] = "NewData";
constexpr char kParseFuncWithBuffer[] = "ParseBuffer";
constexpr char kParseFuncWithoutBuffer[] = "Parse";
constexpr char kRefCountClass[] = "binpac::RefCount";
constexpr char kTypeWithLengthClass[] = "binpac::TypeWithLength";

#endif // pac_common_h
