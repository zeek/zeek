/* $Id: scan.l 6510 2009-01-08 14:51:04Z vern $ */
%{
// See the file "COPYING" in the main distribution directory for copyright.

#include <errno.h>

#include "input.h"
#include "util.h"
#include "Scope.h"
#include "DNS_Mgr.h"
#include "Expr.h"
#include "Func.h"
#include "Stmt.h"
#include "Var.h"
#include "Debug.h"
#include "PolicyFile.h"
#include "broparse.h"

#include <stack>

extern YYLTYPE yylloc;	// holds start line and column of token
extern int print_loaded_scripts;

int nwarn = 0;
int nerr = 0;
int nruntime = 0;

// Track the @if... depth.
ptr_compat_int current_depth = 0;

declare(List,ptr_compat_int);
typedef List(ptr_compat_int) int_list;
int_list if_stack;

int line_number = 1;
int include_level = 0;
const char* filename = 0;

char last_tok[128];

#define YY_USER_ACTION	strncpy(last_tok, yytext, sizeof(last_tok) - 1);
#define YY_USER_INIT	last_tok[0] = '\0';

// We define our own YY_INPUT because we want to trap the case where
// a read fails.
#define YY_INPUT(buf,result,max_size) \
	if ( ((result = fread(buf, 1, max_size, yyin)) == 0) && ferror(yyin) ) \
		error(fmt("read failed with \"%s\"", strerror(errno)));

// Files we have already scanned (or are in the process of scanning).
static PList(char) files_scanned;

class FileInfo {
public:
	FileInfo(string restore_module = "");
	~FileInfo();

	YY_BUFFER_STATE buffer_state;
	string restore_module;
	const char* name;
	int line;
	int level;
};

// A stack of input buffers we're scanning.  file_stack[len-1] is the
// top of the stack.
declare(PList,FileInfo);
static PList(FileInfo) file_stack;

#define RET_CONST(v) \
	{ \
	yylval.val = v; \
	return TOK_CONSTANT; \
	}

// Returns true if the file is new, false if it's already been scanned.
static int load_files_with_prefix(const char* file);

// If print_loaded_files is true, print current filename if we haven't
// reported it already.
static void report_file();

// ### TODO: columns too - use yyless with '.' action?
%}

%option nounput nodefault

%x RE
%x IGNORE

OWS	[ \t]*
WS	[ \t]+
D	[0-9]+
HEX	[0-9a-fA-F]+
IDCOMPONENT [A-Za-z_][A-Za-z_0-9]*
ID	{IDCOMPONENT}(::{IDCOMPONENT})*
FILE	[^ \t\n]+
PREFIX	[^ \t\n]+
FLOAT	(({D}*"."?{D})|({D}"."?{D}*))([eE][-+]?{D})?
H	[A-Za-z0-9][A-Za-z0-9\-]*
ESCSEQ	(\\([^\n]|[0-7]+|x[[:xdigit:]]+))

%%

#.*	/* eat comments */

{WS}	/* eat whitespace */

<INITIAL,IGNORE>\n	{
			report_file();
			++line_number;
			++yylloc.first_line;
			++yylloc.last_line;
			}

[!%*/+\-,:;<=>?()\[\]{}~$|]	return yytext[0];

"--"	return TOK_DECR;
"++"	return TOK_INCR;

"+="	return TOK_ADD_TO;
"-="	return TOK_REMOVE_FROM;

"=="	return TOK_EQ;
"!="	return TOK_NE;
">="	return TOK_GE;
"<="	return TOK_LE;

"&&"	return TOK_AND;
"||"	return TOK_OR;

add	return TOK_ADD;
addr	return TOK_ADDR;
alarm	return TOK_ALARM;
any	return TOK_ANY;
bool	return TOK_BOOL;
break	return TOK_BREAK;
case	return TOK_CASE;
const	return TOK_CONST;
copy	return TOK_COPY;
count	return TOK_COUNT;
counter	return TOK_COUNTER;
default	return TOK_DEFAULT;
delete	return TOK_DELETE;
double	return TOK_DOUBLE;
else	return TOK_ELSE;
enum	return TOK_ENUM;
event	return TOK_EVENT;
export	return TOK_EXPORT;
file	return TOK_FILE;
for	return TOK_FOR;
function	return TOK_FUNCTION;
global	return TOK_GLOBAL;
global_attr	return TOK_GLOBAL_ATTR;
"?$"	return TOK_HAS_FIELD;
"?$$"	return TOK_HAS_ATTR;
if	return TOK_IF;
in	return TOK_IN;
"!"{OWS}in/[^A-Za-z0-9]	return TOK_NOT_IN;	/* don't confuse w "! infoo"! */
int	return TOK_INT;
interval	return TOK_INTERVAL;
list	return TOK_LIST;
local	return TOK_LOCAL;
match	return TOK_MATCH;
module	return TOK_MODULE;
net	return TOK_NET;
next	return TOK_NEXT;
of	return TOK_OF;
pattern	return TOK_PATTERN;
port	return TOK_PORT;
print	return TOK_PRINT;
record	return TOK_RECORD;
redef	return TOK_REDEF;
return	return TOK_RETURN;
schedule	return TOK_SCHEDULE;
set	return TOK_SET;
string	return TOK_STRING;
subnet	return TOK_SUBNET;
switch	return TOK_SWITCH;
table	return TOK_TABLE;
this	return TOK_THIS;
time	return TOK_TIME;
timeout	return TOK_TIMEOUT;
timer	return TOK_TIMER;
type	return TOK_TYPE;
union	return TOK_UNION;
using	return TOK_USING;
vector	return TOK_VECTOR;
when	return TOK_WHEN;

&add_func	return TOK_ATTR_ADD_FUNC;
&attr		return TOK_ATTR_ATTR;
&create_expire	return TOK_ATTR_EXPIRE_CREATE;
&default	return TOK_ATTR_DEFAULT;
&delete_func	return TOK_ATTR_DEL_FUNC;
&disable_print_hook	return TOK_ATTR_DISABLE_PRINT_HOOK;
&raw_output return TOK_ATTR_RAW_OUTPUT;
&encrypt	return TOK_ATTR_ENCRYPT;
&expire_func	return TOK_ATTR_EXPIRE_FUNC;
&group		return TOK_ATTR_GROUP;
&mergeable	return TOK_ATTR_MERGEABLE;
&optional	return TOK_ATTR_OPTIONAL;
&persistent	return TOK_ATTR_PERSISTENT;
&priority	return TOK_ATTR_PRIORITY;
&read_expire	return TOK_ATTR_EXPIRE_READ;
&redef		return TOK_ATTR_REDEF;
&rotate_interval	return TOK_ATTR_ROTATE_INTERVAL;
&rotate_size		return TOK_ATTR_ROTATE_SIZE;
&synchronized	return TOK_ATTR_SYNCHRONIZED;
&write_expire	return TOK_ATTR_EXPIRE_WRITE;

@DEBUG	return TOK_DEBUG;	// marks input for debugger

@load{WS}{FILE}	{
	const char* new_file = skip_whitespace(yytext + 5);	// Skip "@load".
	(void) load_files_with_prefix(new_file);
	}

@unload{WS}{FILE}	{
	// Skip "@unload".
	const char* new_file = skip_whitespace(yytext + 7);

	// All we have to do is pretend we've already scanned it.
	files_scanned.append(copy_string(new_file));
	}

@prefixes{WS}("+"?)={WS}{PREFIX}	{
	char* pref = skip_whitespace(yytext + 9);	// Skip "@prefixes".

	int append = 0;
	if ( *pref == '+' )
		{
		append = 1;
		++pref;
		}

	pref = skip_whitespace(pref + 1);	// Skip over '='.

	if ( ! append )
		while ( prefixes.length() > 1 )	// don't delete "" prefix
			delete prefixes.remove_nth(1);

	add_to_name_list(pref, ':', prefixes);
	}

@if	return TOK_ATIF;
@ifdef	return TOK_ATIFDEF;
@ifndef	return TOK_ATIFNDEF;
@else   return TOK_ATELSE;
@endif	--current_depth;

<IGNORE>@if	++current_depth;
<IGNORE>@ifdef	++current_depth;
<IGNORE>@ifndef	++current_depth;
<IGNORE>@else   return TOK_ATELSE;
<IGNORE>@endif	return TOK_ATENDIF;
<IGNORE>[^@\n]+	/* eat */
<IGNORE>.	/* eat */

T	RET_CONST(new Val(true, TYPE_BOOL))
F	RET_CONST(new Val(false, TYPE_BOOL))

{ID}	{
	yylval.str = copy_string(yytext);
	return TOK_ID;
	}

{D}		{
 		// TODO: check if we can use strtoull instead of atol, 
		// and similarly for {HEX}.
		RET_CONST(new Val(static_cast<unsigned int>(atol(yytext)), 
			  TYPE_COUNT))		
		}
{FLOAT}		RET_CONST(new Val(atof(yytext), TYPE_DOUBLE))

{D}"/tcp"	{
		uint32 p = atoi(yytext);
		if ( p > 65535 )
			{
			error("bad port number -", yytext);
			p = 0;
			}
		RET_CONST(new PortVal(p, TRANSPORT_TCP))
		}
{D}"/udp"	{
		uint32 p = atoi(yytext);
		if ( p > 65535 )
			{
			error("bad port number -", yytext);
			p = 0;
			}
		RET_CONST(new PortVal(p, TRANSPORT_UDP))
		}
{D}"/icmp"	{
		uint32 p = atoi(yytext);
		if ( p > 255 )
			{
			error("bad port number -", yytext);
			p = 0;
			}
		RET_CONST(new PortVal(p, TRANSPORT_ICMP))
		}
{D}"/unknown"	{
		uint32 p = atoi(yytext);
		if ( p > 255 )
			{
			error("bad port number -", yytext);
			p = 0;
			}
		RET_CONST(new PortVal(p, TRANSPORT_UNKNOWN))
		}

{D}"."{D}"."		RET_CONST(new NetVal(yytext))
({D}"."){2}{D}		RET_CONST(new NetVal(yytext))
({D}"."){3}{D}		RET_CONST(new AddrVal(yytext))

({HEX}:){7}{HEX}	RET_CONST(new AddrVal(yytext))

0x{HEX}({HEX}|:)*"::"({HEX}|:)*	RET_CONST(new AddrVal(yytext+2))
(({D}|:)({HEX}|:)*)?"::"({HEX}|:)*	RET_CONST(new AddrVal(yytext))

"0x"{HEX}+	RET_CONST(new Val(static_cast<bro_uint_t>(strtol(yytext, 0, 16)), TYPE_COUNT))

{H}("."{H})+		RET_CONST(dns_mgr->LookupHost(yytext))

{FLOAT}{OWS}day(s?)	RET_CONST(new IntervalVal(atof(yytext),Days))
{FLOAT}{OWS}hr(s?)	RET_CONST(new IntervalVal(atof(yytext),Hours))
{FLOAT}{OWS}min(s?)	RET_CONST(new IntervalVal(atof(yytext),Minutes))
{FLOAT}{OWS}sec(s?)	RET_CONST(new IntervalVal(atof(yytext),Seconds))
{FLOAT}{OWS}msec(s?)	RET_CONST(new IntervalVal(atof(yytext),Milliseconds))
{FLOAT}{OWS}usec(s?)	RET_CONST(new IntervalVal(atof(yytext),Microseconds))

\"([^\\\n\"]|{ESCSEQ})*\"	{
	const char* text = yytext;
	int len = strlen(text) + 1;
	int i = 0;

	char* s = new char[len];

	// Skip leading quote.
	for ( ++text; *text; ++text )
		{
		if ( *text == '\\' )
			{
			++text;	// skip '\'
			s[i++] = expand_escape(text);
			--text;	// point to end of sequence
			}
		else
			{
			s[i++] = *text;
			if ( i >= len )
				internal_error("bad string length computation");
			}
		}

	// Get rid of trailing quote.
	if ( s[i-1] != '"' )
		internal_error("string scanning confused");

	s[i-1] = '\0';

	RET_CONST(new StringVal(new BroString(1, (byte_vec) s, i-1)))
	}

<RE>([^/\\\n]|{ESCSEQ})+	{
	yylval.str = copy_string(yytext);
	return TOK_PATTERN_TEXT;
	}

<RE>[/\\\n]	return yytext[0];

<*>.	error("unrecognized character -", yytext);

<<EOF>>	last_tok[0] = '\0'; return EOF;

%%

YYLTYPE GetCurrentLocation()
	{
	static YYLTYPE currloc;

	currloc.filename = filename;
	currloc.first_line = currloc.last_line = line_number;

	return currloc;
	}

static int load_files_with_prefix(const char* orig_file)
	{
	loop_over_list(files_scanned, j)
		{
		if ( streq(files_scanned[j], orig_file) )
			return 0;
		}

	// Be sure to copy "orig_file", since it could be an alias
	// for yytext, which is ephemeral and will be zapped
	// if we do a yy_switch_to_buffer() below.
	char* file = copy_string(orig_file);

	// Whether we pushed on a FileInfo that will restore the
	// current module after the final file has been scanned. 
	bool did_module_restore = false;

	files_scanned.append(file);

	// If the file has a .bro extension, add a second version to the list
	// of known files which has it stripped.
	char* ext = strrchr(file, '.');
	if ( ext && streq(ext, ".bro") )
		{
		char* s = copy_string(file);
		s[ext - file] = '\0';
		files_scanned.append(s);
		}

	// Note, we need to loop through the prefixes backwards, since
	// we push them onto a stack, with the last one we push on the
	// stack being the first one we will scan.
	for ( int i = prefixes.length() - 1; i >= 0; --i )
		{
		const char* prefix = prefixes[i];

		const char* full_filename = "<internal error>";
		FILE* f;

		if ( streq(file, "-") )
			{
			f = stdin;
			full_filename = "<stdin>";

			if ( g_policy_debug )
				{
				debug_msg("Warning: can't use debugger while reading policy from stdin; turning off debugging.\n");
				g_policy_debug = false;
				}
			}

		else
			{
			int n = strlen(prefix) + strlen(file) + 2;
			char* new_filename = new char[n];

			if ( prefix[0] )
				sprintf(new_filename, "%s.%s", prefix, file);
			else
				strcpy(new_filename, file);

			f = search_for_file(new_filename, "bro", &full_filename);

			delete [] new_filename;
			}

		if ( f )
			{
			if ( g_policy_debug )
				{
				// Add the filename to the file mapping
				// table (Debug.h).
				Filemap* map = new Filemap;

				// Make sure it wasn't already read in.
				HashKey* key = new HashKey(full_filename);
				if ( g_dbgfilemaps.Lookup(key) )
					{
					// warn("Not re-reading policy file; check BRO_PREFIXES:", full_filename);
					fclose(f);
					delete key;
					continue;
					}
				else
					{
					g_dbgfilemaps.Insert(key, map);
					}

				if ( full_filename )
					LoadPolicyFileText(full_filename);
				}

			// Remember where we were.  If this is the first
			// file being pushed on the stack, i.e., the *last*
			// one that will be processed, then we want to
			// restore the module scope in which this @load
			// was done when we're finished processing it.
			if ( ! did_module_restore )
				{
				file_stack.append(new FileInfo(current_module));
				did_module_restore = true;
				}
			else
				file_stack.append(new FileInfo);

			yy_switch_to_buffer(yy_create_buffer(f, YY_BUF_SIZE));

			yylloc.first_line = yylloc.last_line = line_number = 1;

			// Don't delete the old filename - it's pointed to by
			// every BroObj created when parsing it.
			yylloc.filename = filename = full_filename;
			}

		else
			{
			if ( streq(prefixes[i], "") )
				{
				error("can't open", full_filename);
				exit(1);
				}
			}
		}

	return 1;
	}

void begin_RE()
	{
	BEGIN(RE);
	}

void end_RE()
	{
	BEGIN(INITIAL);
	}

void do_atif(Expr* expr)
	{
	++current_depth;

	Val* val = expr->Eval(0);
	if ( ! val->AsBool() )
		{
		if_stack.append(current_depth);
		BEGIN(IGNORE);
		}
	}

void do_atifdef(const char* id)
	{
	++current_depth;

	if ( ! lookup_ID(id, current_module.c_str()) )
		{
		if_stack.append(current_depth);
		BEGIN(IGNORE);
		}
	}

void do_atifndef(const char *id)
	{
	++current_depth;

	if ( lookup_ID(id, current_module.c_str()) )
		{
		if_stack.append(current_depth);
		BEGIN(IGNORE);
		}
	}

void do_atelse()
	{
	if ( current_depth == 0 )
		error("@else without @if...");

	if ( if_stack.length() && current_depth > if_stack.last() )
		return;

	if ( YY_START == INITIAL )
		{
		if_stack.append(current_depth);
		BEGIN(IGNORE);
		}
	else
		{
		if_stack.get();
		BEGIN(INITIAL);
		}
	}

void do_atendif()
	{
	if ( current_depth == 0 )
		error("unbalanced @if... @endif");

	if ( current_depth == if_stack.last() )
		{
		BEGIN(INITIAL);
		if_stack.get();
		}

	--current_depth;
	}

// Be careful to never delete things from this list, as the strings
// are referred to (in order to save the locations of tokens and statements,
// for error reporting and debugging).
static name_list input_files;

const char* get_current_input_filename()
	{
	return ::filename;
	}

void add_input_file(const char* file)
	{
	if ( ! file )
		internal_error("empty filename");

	if ( ! filename )
		(void) load_files_with_prefix(file);
	else
		input_files.append(copy_string(file));
	}

void add_to_name_list(char* s, char delim, name_list& nl)
	{
	while ( s )
		{
		char* s_delim = strchr(s, delim);
		if ( s_delim )
			*s_delim = 0;

		nl.append(copy_string(s));

		if ( s_delim )
			s = s_delim + 1;
		else
			break;
		}
	}

int yywrap()
	{
	if ( nerr > 0 )
		return 1;

	--include_level;

	if ( ! did_builtin_init && file_stack.length() == 1 )
		{
		// ### This is a gross hack - we know that the first file
		// we parse is bro.init, and after it it's safe to initialize
		// the built-ins.  Furthermore, we want to initialize the
		// built-in's *right* after parsing bro.init, so that other
		// source files can use built-in's when initializing globals.
		init_builtin_funcs();
		}

	yy_delete_buffer(YY_CURRENT_BUFFER);

	delete file_stack.remove_nth(file_stack.length() - 1);

	if ( YY_CURRENT_BUFFER )
		// There's more on the stack to scan.
		return 0;

	// Stack is now empty.
	while ( input_files.length() > 0 )
		{
		if ( load_files_with_prefix(input_files[0]) )
			{
			// Don't delete the filename - it's pointed to by
			// every BroObj created when parsing it.
			(void) input_files.remove_nth(0);
			return 0;
			}

		// We already scanned the file.  Pop it and try the next,
		// if any.
		(void) input_files.remove_nth(0);
		}

	// Add redef statements for any X=Y command line parameters.
	if ( params.size() > 0 )
		{
		string policy;

		for ( unsigned int i = 0; i < params.size(); ++i )
			{
			char* param = copy_string(params[i].c_str());
			char* eq = strchr(param, '=');
			char* val = eq + 1;

			*eq = '\0';

			if ( strlen(val) == 0 )
				{
				delete [] param;
				continue;
				}

			// Try to find the type of the param, and interpret
			// the value intelligently for that type.  (So far,
			// that just means quoting the value if it's a
			// string type.)  If no type is found, the value
			// is left unchanged.
			string opt_quote;	// no optional quote by default
			Val* v = opt_internal_val(param);

			if ( v && v->Type() && v->Type()->Tag() == TYPE_STRING )
				opt_quote = "\"";	// use quotes

			policy += string("redef ") + param + "="
					+ opt_quote + val + opt_quote + ";";

			delete [] param;
			}

		params.clear();
		yylloc.filename = filename = "<params>";
		yy_scan_string(policy.c_str());
		return 0;
		}

	// If we got this far, then we ran out of files. Check if the user
	// specified additional code on the command line, if so, parse it.
	// Use a synthetic filename, and add an extra semicolon on its own
	// line (so that things like @load work), so that a semicolon is
	// not strictly necessary.
	if ( command_line_policy )
		{
		int tmp_len = strlen(command_line_policy) + 32;
		char* tmp = new char[tmp_len];
		snprintf(tmp, tmp_len, "%s\n;\n", command_line_policy);
		yylloc.filename = filename = "<command line>";

		yy_scan_string(tmp);
		delete [] tmp;

		// Make sure we do not get here again:
		command_line_policy = 0;

		return 0;
		}

	// Otherwise, we are done.
	return 1;
	}

FileInfo::FileInfo(string arg_restore_module)
	{
	buffer_state = YY_CURRENT_BUFFER;
	restore_module = arg_restore_module;
	name = ::filename;
	line = ::line_number;
	level = ::include_level;
	}

FileInfo::~FileInfo()
	{
	if ( yyin && yyin != stdin )
		fclose(yyin);

	yy_switch_to_buffer(buffer_state);
	yylloc.filename = filename = name;
	yylloc.first_line = yylloc.last_line = line_number = line;
	include_level = level;

	if ( restore_module != "" )
		current_module = restore_module;
	}

static void report_file()
	{
	if ( ! print_loaded_scripts || ! filename )
		return;

	static PList(char) files_reported;

	loop_over_list(files_reported, i)
		{
		if ( streq(files_reported[i], filename) )
			return;
		}

	for ( int i = include_level - 1; i >= 0; --i )
		fprintf(stderr, "   ");
	fprintf(stderr, "loading %s\n", filename);

	++include_level;
	files_reported.append(copy_string(filename));
	}

