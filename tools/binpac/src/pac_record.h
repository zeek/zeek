#ifndef pac_record_h
#define pac_record_h

#include "pac_common.h"
#include "pac_field.h"
#include "pac_id.h"
#include "pac_let.h"
#include "pac_type.h"

class RecordType : public Type
{
public:
	RecordType(RecordFieldList* fields);
	~RecordType();

	bool DefineValueVar() const;
	string DataTypeStr() const;

	void Prepare(Env* env, int flags);

	void GenPubDecls(Output* out, Env* env);
	void GenPrivDecls(Output* out, Env* env);

	void GenInitCode(Output* out, Env* env);
	void GenCleanUpCode(Output* out, Env* env);

	int StaticSize(Env* env) const;

	void SetBoundaryChecked();

	const ID *parsing_dataptr_var() const;

	bool IsPointerType() const	{ ASSERT(0); return false; }

protected:
	void DoGenParseCode(Output* out, Env* env, const DataPtr& data, int flags);
	void GenDynamicSize(Output* out, Env* env, const DataPtr& data);

	Type *DoClone() const 	{ return 0; }

	void DoMarkIncrementalInput();

	bool DoTraverse(DataDepVisitor *visitor);
	bool ByteOrderSensitive() const;

private:
	Field *parsing_dataptr_var_field_;
	RecordFieldList* record_fields_;
};

// A data field of a record type. A RecordField corresponds to a
// segment of input data, and therefore RecordField's are ordered---each
// of them has a known previous and next field.

class RecordField : public Field
{
public:
	RecordField(FieldType tof, ID* id, Type *type);
	~RecordField();

	RecordType *record_type() const		{ return record_type_; }
	void set_record_type(RecordType* ty) 	{ record_type_ = ty; }

	virtual void GenParseCode(Output* out, Env* env) = 0;

	RecordField* prev() const		{ return prev_; }
	RecordField* next() const		{ return next_; }
	void set_prev(RecordField* f) 		{ prev_ = f; }
	void set_next(RecordField* f) 		{ next_ = f; }

	int static_offset() const 		{ return static_offset_; }
	void set_static_offset(int offset)	{ static_offset_ = offset; }

	int parsing_state_seq() const		{ return parsing_state_seq_; }
	void set_parsing_state_seq(int x) 	{ parsing_state_seq_ = x; }

	virtual int StaticSize(Env* env, int offset) const = 0;
	const char* FieldSize(Output* out, Env* env);
	const char* FieldOffset(Output* out, Env* env);

	virtual bool BoundaryChecked() const	{ return boundary_checked_; }
	virtual void SetBoundaryChecked()	{ boundary_checked_ = true; }

	virtual bool RequiresByteOrder() const = 0;

	friend class RecordType;

protected:
	RecordType* record_type_;
	RecordField* prev_;
	RecordField* next_;
	bool boundary_checked_;
	int static_offset_;
	int parsing_state_seq_;

	DataPtr* begin_of_field_dataptr;
	DataPtr* end_of_field_dataptr;
	char* field_size_expr;
	char* field_offset_expr;
	ID* end_of_field_dataptr_var;

	const DataPtr& getFieldBegin(Output* out_cc, Env* env);
	const DataPtr& getFieldEnd(Output* out_cc, Env* env);
	virtual void GenFieldEnd(Output* out, Env* env, const DataPtr& begin) = 0; 

	bool AttemptBoundaryCheck(Output* out_cc, Env* env);
	virtual bool GenBoundaryCheck(Output* out_cc, Env* env) = 0;
};

class RecordDataField : public RecordField, public Evaluatable
{
public:
	RecordDataField(ID* arg_id, Type* arg_type);
	~RecordDataField();

	// Instantiates abstract class Field
	void Prepare(Env* env);
	void GenParseCode(Output* out, Env* env);

	// Instantiates abstract class Evaluatable
	void GenEval(Output* out, Env* env);

	int StaticSize(Env* env, int) const 	{ return type()->StaticSize(env); }

	void SetBoundaryChecked();

	bool RequiresByteOrder() const
		{ return type()->RequiresByteOrder(); }
	bool RequiresAnalyzerContext() const;

protected:
	void GenFieldEnd(Output* out, Env* env, const DataPtr& begin); 
	bool GenBoundaryCheck(Output* out_cc, Env* env);
	bool DoTraverse(DataDepVisitor *visitor);
};

enum PaddingType { PAD_BY_LENGTH, PAD_TO_OFFSET, PAD_TO_NEXT_WORD };

class RecordPaddingField : public RecordField
{
public:
	RecordPaddingField(ID* id, PaddingType ptype, Expr* expr);
	~RecordPaddingField();

	void Prepare(Env* env);

	void GenPubDecls(Output* out, Env* env) 	{ /* nothing */ }
	void GenPrivDecls(Output* out, Env* env) 	{ /* nothing */ }

	void GenInitCode(Output* out, Env* env) 	{ /* nothing */ }
	void GenCleanUpCode(Output* out, Env* env)	{ /* nothing */ }
	void GenParseCode(Output* out, Env* env);

	int StaticSize(Env* env, int offset) const;

	bool RequiresByteOrder() const		{ return false; }

protected:
	void GenFieldEnd(Output* out, Env* env, const DataPtr& begin); 
	bool GenBoundaryCheck(Output* out_cc, Env* env);
	bool DoTraverse(DataDepVisitor *visitor);

private:
	PaddingType ptype_;
	Expr* expr_;
	int wordsize_;
};

#endif  // pac_record_h
