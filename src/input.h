// $Id: input.h 6219 2008-10-01 05:39:07Z vern $
//
// See the file "COPYING" in the main distribution directory for copyright.

#ifndef input_h
#define input_h

#include <vector>
#include <string>
using namespace std;

#include "BroList.h"

extern int yyparse();
extern int yydebug;
extern int brolex();
extern char last_tok[128];

extern void add_input_file(const char* file);

// Adds the substrings (using the given delimiter) in a string to the
// given namelist.
extern void add_to_name_list(char* s, char delim, name_list& nl);

extern void begin_RE();
extern void end_RE();

extern void do_atif(Expr* expr);
extern void do_atifdef(const char* id);
extern void do_atifndef(const char* id);
extern void do_atelse();
extern void do_atendif();

extern int line_number;
extern const char* filename;

extern int bro_argc;
extern char** bro_argv;
extern const char* prog;

extern name_list prefixes;	// -p flag
extern char* command_line_policy;	// -e flag
extern vector<string> params;

class Stmt;
extern Stmt* stmts;	// global statements

extern int optimize;

extern int nwarn;
extern int nerr;
extern int nruntime;

#endif
