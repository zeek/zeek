// See the file "COPYING" in the main distribution directory for copyright.

// ZBody: ZAM function body

#pragma once

#include "ZOP.h"


// Static information about globals used in a function.  There's a parallel
// array "global_state" that's constructed per-function-invocation that
// dynamically tracks whether a global is loaded, clean, or dirty.
class GlobalInfo {
public:
	ID* id;
	int slot;
};

class ZBody : public Stmt {
public:
	// These are the counterparts to CaseMapI and CaseMapsI in ZAM.h,
	// but now concretized to use instruction numbers rather than pointers
	// to instructions.
	template<class T> using CaseMap = std::map<T, int>;
	template<class T> using CaseMaps = std::vector<CaseMap<T>>;

	ZBody(const char* _func_name, vector<ZInstI*>& instsI,
		FrameReMap& _frame_denizens, std::vector<int>& _managed_slots,
		std::vector<GlobalInfo>& _globals, bool non_recursive,
		CaseMaps<bro_int_t>& _int_cases,
		CaseMaps<bro_uint_t>& _uint_cases,
		CaseMaps<double>& _double_cases,
		CaseMaps<std::string>& _str_cases);

	~ZBody() override;

	IntrusivePtr<Val> Exec(Frame* f, stmt_flow_type& flow) const override;

	void SaveTo(FILE* f) const;

	void ProfileExecution() const;

protected:
	friend class ResumptionAM;

	IntrusivePtr<Val> DoExec(Frame* f, int start_pc,
					stmt_flow_type& flow) const;

	// Run-time checking for "any" type being consistent with
	// expected typed.  Returns true if the type match is okay.
	bool CheckAnyType(const BroType* any_type, const BroType* expected_type,
				const Location* loc) const;

	IntrusivePtr<Stmt> Duplicate() override	{ return {NewRef{}, this}; }

	void Dump();
	void StmtDescribe(ODesc* d) const override;
	TraversalCode Traverse(TraversalCallback* cb) const override;

	const char* func_name;

	vector<ZInst*> insts;

	// The same, but renumbered to take into account removal of
	// dead statements.
	FrameReMap frame_denizens;
	int frame_size;

	std::vector<int> managed_slots;

	// This is non-nil if the function is (asserted to be) non-recursive,
	// in which case we pre-allocate this.
	ZAMValUnion* fixed_frame = nullptr;

	std::vector<GlobalInfo> globals;
	int num_globals;

	// The following are only maintained if we're doing profiling.
	//
	// These need to be pointers so we can manipulate them in a
	// const method.
	vector<int>* inst_count = nullptr;	// for profiling
	double* CPU_time = nullptr;	// cumulative CPU time for the program
	vector<double>* inst_CPU;	// per-instruction CPU time.

	CaseMaps<bro_int_t> int_cases;
	CaseMaps<bro_uint_t> uint_cases;
	CaseMaps<double> double_cases;
	CaseMaps<std::string> str_cases;
};

// This is a statement that resumes execution into a code block in a
// ZBody.  Used for deferred execution for "when" statements.
class ResumptionAM : public Stmt {
public:
	ResumptionAM(const ZBody* _am, int _xfer_pc)
		{
		am = _am;
		xfer_pc = _xfer_pc;
		}

	IntrusivePtr<Val> Exec(Frame* f, stmt_flow_type& flow) const override;

	IntrusivePtr<Stmt> Duplicate() override	{ return {NewRef{}, this}; }

	void StmtDescribe(ODesc* d) const override;

protected:
	TraversalCode Traverse(TraversalCallback* cb) const override;

	const ZBody* am;
	int xfer_pc = 0;
};

// Needed for logging built-in.  Exported so that ZAM can make sure it's
// defined when compiling.
extern BroType* log_ID_enum_type;

extern void report_ZOP_profile();

extern void ZAM_run_time_error(const Stmt* stmt, const char* msg);
extern void ZAM_run_time_error(const char* msg, const BroObj* o);

extern StringVal* ZAM_to_lower(const StringVal* sv);
extern StringVal* ZAM_sub_bytes(const StringVal* s, bro_uint_t start,
				bro_int_t n);
