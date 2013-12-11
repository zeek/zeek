%{
// See the file "COPYING" in the main distribution directory for copyright.

#include <errno.h>

#include <stack>
#include <list>
#include <string>
#include <algorithm>
#include <sys/stat.h>
#include <sys/param.h>
#include <unistd.h>
#include <libgen.h>

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
#include "Reporter.h"
#include "RE.h"
#include "Net.h"

#include "analyzer/Analyzer.h"
#include "broxygen/Manager.h"

extern YYLTYPE yylloc;	// holds start line and column of token
extern EnumType* cur_enum_type;

// Track the @if... depth.
ptr_compat_int current_depth = 0;

int_list if_stack;

int line_number = 1;
const char* filename = 0; // Absolute path of file currently being parsed.
static const char* last_id_tok = 0;

char last_tok[128];

#define YY_USER_ACTION	strncpy(last_tok, yytext, sizeof(last_tok) - 1);
#define YY_USER_INIT	last_tok[0] = '\0';

// We define our own YY_INPUT because we want to trap the case where
// a read fails.
#define YY_INPUT(buf,result,max_size) \
	if ( ((result = fread(buf, 1, max_size, yyin)) == 0) && ferror(yyin) ) \
		reporter->Error("read failed with \"%s\"", strerror(errno));

static string find_relative_file(const string& filename, const string& ext)
	{
	if ( filename.empty() )
		return string();

	if ( filename[0] == '.' )
		return find_file(filename, SafeDirname(::filename).result, ext);
	else
		return find_file(filename, bro_path(), ext);
	}

static ino_t get_inode_num(FILE* f, const string& path)
	{
	struct stat b;

	if ( fstat(fileno(f), &b) )
		reporter->FatalError("fstat of %s failed: %s\n", path.c_str(),
		                     strerror(errno));

	return b.st_ino;
	}

static ino_t get_inode_num(const string& path)
	{
	FILE* f = open_file(path);

	if ( ! f )
		reporter->FatalError("failed to open %s\n", path.c_str());

	return get_inode_num(f, path);
	}

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
static int load_files(const char* file);

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
IP6 ("["({HEX}:){7}{HEX}"]")|("["0x{HEX}({HEX}|:)*"::"({HEX}|:)*"]")|("["({HEX}|:)*"::"({HEX}|:)*"]")|("["({HEX}|:)*"::"({HEX}|:)*({D}"."){3}{D}"]")
FILE	[^ \t\n]+
PREFIX	[^ \t\n]+
FLOAT	(({D}*"."?{D})|({D}"."?{D}*))([eE][-+]?{D})?
H	[A-Za-z0-9][A-Za-z0-9\-]*
ESCSEQ	(\\([^\n]|[0-7]+|x[[:xdigit:]]+))

%%

##!.* {
	broxygen_mgr->SummaryComment(::filename, yytext + 3);
	}

##<.* {
	string hint(cur_enum_type && last_id_tok ?
	            make_full_var_name(current_module.c_str(), last_id_tok) : "");

	broxygen_mgr->PostComment(yytext + 3, hint);
}

##.* {
	if ( yytext[2] != '#' )
		broxygen_mgr->PreComment(yytext + 2);
}

#{OWS}@no-test.* return TOK_NO_TEST;

#.*	/* eat comments */

{WS}	/* eat whitespace */

<INITIAL,IGNORE>\n	{
			++line_number;
			++yylloc.first_line;
			++yylloc.last_line;
			}

	/* IPv6 literal constant patterns */
{IP6}	{
	RET_CONST(new AddrVal(extract_ip(yytext)))
}

{IP6}{OWS}"/"{OWS}{D}	{
	int len = 0;
	string ip = extract_ip_and_len(yytext, &len);
	RET_CONST(new SubNetVal(IPPrefix(IPAddr(ip), len, true)))
}

	/* IPv4 literal constant patterns */
({D}"."){3}{D}		RET_CONST(new AddrVal(yytext))

({D}"."){3}{D}{OWS}"/"{OWS}{D}	{
	int len = 0;
	string ip = extract_ip_and_len(yytext, &len);
	RET_CONST(new SubNetVal(IPPrefix(IPAddr(ip), len)))
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
fallthrough	return TOK_FALLTHROUGH;
file	return TOK_FILE;
for	return TOK_FOR;
function	return TOK_FUNCTION;
global	return TOK_GLOBAL;
"?$"	return TOK_HAS_FIELD;
hook	return TOK_HOOK;
if	return TOK_IF;
in	return TOK_IN;
"!"{OWS}in/[^A-Za-z0-9]	return TOK_NOT_IN;	/* don't confuse w "! infoo"! */
int	return TOK_INT;
interval	return TOK_INTERVAL;
list	return TOK_LIST;
local	return TOK_LOCAL;
module	return TOK_MODULE;
next	return TOK_NEXT;
of	return TOK_OF;
opaque	return TOK_OPAQUE;
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
time	return TOK_TIME;
timeout	return TOK_TIMEOUT;
timer	return TOK_TIMER;
type	return TOK_TYPE;
union	return TOK_UNION;
vector	return TOK_VECTOR;
when	return TOK_WHEN;

&add_func	return TOK_ATTR_ADD_FUNC;
&create_expire	return TOK_ATTR_EXPIRE_CREATE;
&default	return TOK_ATTR_DEFAULT;
&delete_func	return TOK_ATTR_DEL_FUNC;
&raw_output return TOK_ATTR_RAW_OUTPUT;
&encrypt	return TOK_ATTR_ENCRYPT;
&error_handler	return TOK_ATTR_ERROR_HANDLER;
&expire_func	return TOK_ATTR_EXPIRE_FUNC;
&log		return TOK_ATTR_LOG;
&mergeable	return TOK_ATTR_MERGEABLE;
&optional	return TOK_ATTR_OPTIONAL;
&persistent	return TOK_ATTR_PERSISTENT;
&priority	return TOK_ATTR_PRIORITY;
&type_column	return TOK_ATTR_TYPE_COLUMN;
&read_expire	return TOK_ATTR_EXPIRE_READ;
&redef		return TOK_ATTR_REDEF;
&rotate_interval	return TOK_ATTR_ROTATE_INTERVAL;
&rotate_size		return TOK_ATTR_ROTATE_SIZE;
&synchronized	return TOK_ATTR_SYNCHRONIZED;
&write_expire	return TOK_ATTR_EXPIRE_WRITE;

@DEBUG	return TOK_DEBUG;	// marks input for debugger

@DIR	{
	string rval = SafeDirname(::filename).result;

	if ( ! rval.empty() && rval[0] == '.' )
		{
		char path[MAXPATHLEN];

		if ( ! getcwd(path, MAXPATHLEN) )
			reporter->InternalError("getcwd failed: %s", strerror(errno));
		else
			rval = string(path) + "/" + rval;
		}

	RET_CONST(new StringVal(rval.c_str()));
	}

@FILENAME	{
	RET_CONST(new StringVal(SafeBasename(::filename).result));
	}

@load{WS}{FILE}	{
	const char* new_file = skip_whitespace(yytext + 5);	// Skip "@load".
	string loader = ::filename;  // load_files may change ::filename, save copy
	string loading = find_relative_file(new_file, "bro");
	(void) load_files(new_file);
	broxygen_mgr->ScriptDependency(loader, loading);
	}

@load-sigs{WS}{FILE} {
	const char* file = skip_whitespace(yytext + 10);
	string path = find_relative_file(file, "sig");

	if ( path.empty() )
		reporter->Error("failed to find file associated with @load-sigs %s",
		                file);
	else
		sig_files.push_back(copy_string(path.c_str()));
	}

@unload{WS}{FILE}	{
	// Skip "@unload".
	const char* file = skip_whitespace(yytext + 7);
	string path = find_relative_file(file, "bro");

	if ( path.empty() )
		reporter->Error("failed find file associated with @unload %s", file);
	else
		{
		// All we have to do is pretend we've already scanned it.
		ScannedFile sf(get_inode_num(path), file_stack.length(), path, true);
		files_scanned.push_back(sf);
		}
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
	last_id_tok = yylval.str;
	return TOK_ID;
	}

{D}		{
		RET_CONST(new Val(static_cast<bro_uint_t>(strtoull(yytext, (char**) NULL, 10)),
			  TYPE_COUNT))
		}
{FLOAT}		RET_CONST(new Val(atof(yytext), TYPE_DOUBLE))

{D}"/tcp"	{
		uint32 p = atoi(yytext);
		if ( p > 65535 )
			{
			reporter->Error("bad port number - %s", yytext);
			p = 0;
			}
		RET_CONST(new PortVal(p, TRANSPORT_TCP))
		}
{D}"/udp"	{
		uint32 p = atoi(yytext);
		if ( p > 65535 )
			{
			reporter->Error("bad port number - %s", yytext);
			p = 0;
			}
		RET_CONST(new PortVal(p, TRANSPORT_UDP))
		}
{D}"/icmp"	{
		uint32 p = atoi(yytext);
		if ( p > 255 )
			{
			reporter->Error("bad port number - %s", yytext);
			p = 0;
			}
		RET_CONST(new PortVal(p, TRANSPORT_ICMP))
		}
{D}"/unknown"	{
		uint32 p = atoi(yytext);
		if ( p > 255 )
			{
			reporter->Error("bad port number - %s", yytext);
			p = 0;
			}
		RET_CONST(new PortVal(p, TRANSPORT_UNKNOWN))
		}

{FLOAT}{OWS}day(s?)	RET_CONST(new IntervalVal(atof(yytext),Days))
{FLOAT}{OWS}hr(s?)	RET_CONST(new IntervalVal(atof(yytext),Hours))
{FLOAT}{OWS}min(s?)	RET_CONST(new IntervalVal(atof(yytext),Minutes))
{FLOAT}{OWS}sec(s?)	RET_CONST(new IntervalVal(atof(yytext),Seconds))
{FLOAT}{OWS}msec(s?)	RET_CONST(new IntervalVal(atof(yytext),Milliseconds))
{FLOAT}{OWS}usec(s?)	RET_CONST(new IntervalVal(atof(yytext),Microseconds))

"0x"{HEX}+	RET_CONST(new Val(static_cast<bro_uint_t>(strtoull(yytext, 0, 16)), TYPE_COUNT))

{H}("."{H})+		RET_CONST(dns_mgr->LookupHost(yytext))

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
				reporter->InternalError("bad string length computation");
			}
		}

	// Get rid of trailing quote.
	if ( s[i-1] != '"' )
		reporter->InternalError("string scanning confused");

	s[i-1] = '\0';

	RET_CONST(new StringVal(new BroString(1, (byte_vec) s, i-1)))
	}

<RE>([^/\\\n]|{ESCSEQ})+	{
	yylval.str = copy_string(yytext);
	return TOK_PATTERN_TEXT;
	}

<RE>[/\\\n]	return yytext[0];

<*>.	reporter->Error("unrecognized character - %s", yytext);

<<EOF>>	last_tok[0] = '\0'; return EOF;

%%

YYLTYPE GetCurrentLocation()
	{
	static YYLTYPE currloc;

	currloc.filename = filename;
	currloc.first_line = currloc.last_line = line_number;

	return currloc;
	}


static bool already_scanned(ino_t i)
	{
	list<ScannedFile>::const_iterator it;

	for ( it = files_scanned.begin(); it != files_scanned.end(); ++it )
		if ( it->inode == i )
			return true;

	return false;
	}

static bool already_scanned(const string& path)
	{
	return already_scanned(get_inode_num(path));
	}

static int load_files(const char* orig_file)
	{
	// Whether we pushed on a FileInfo that will restore the
	// current module after the final file has been scanned.
	bool did_module_restore = false;
	string file_path;
	FILE* f = 0;

	if ( streq(orig_file, "-") )
		{
		f = stdin;
		file_path = "<stdin>";

		if ( g_policy_debug )
			{
			debug_msg("Warning: can't use debugger while reading policy from stdin; turning off debugging.\n");
			g_policy_debug = false;
			}
		}

	else
		{
		file_path = find_relative_file(orig_file, "bro");

		if ( file_path.empty() )
			reporter->FatalError("can't find %s", orig_file);

		if ( is_dir(file_path.c_str()) )
			f = open_package(file_path);
		else
			f = open_file(file_path);

		if ( ! f )
			reporter->FatalError("can't open %s", file_path.c_str());
		}

	ino_t i = get_inode_num(f, file_path);

	if ( already_scanned(i) )
		return 0;

	ScannedFile sf(i, file_stack.length(), file_path);
	files_scanned.push_back(sf);

	if ( g_policy_debug && ! file_path.empty() )
		{
		// Add the filename to the file mapping table (Debug.h).
		Filemap* map = new Filemap;
		HashKey* key = new HashKey(file_path.c_str());
		g_dbgfilemaps.Insert(key, map);
		LoadPolicyFileText(file_path.c_str());
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

	broxygen_mgr->Script(file_path);

	// "orig_file", could be an alias for yytext, which is ephemeral
	//  and will be zapped after the yy_switch_to_buffer() below.
	yy_switch_to_buffer(yy_create_buffer(f, YY_BUF_SIZE));

	yylloc.first_line = yylloc.last_line = line_number = 1;

	// Don't delete the old filename - it's pointed to by
	// every BroObj created when parsing it.
	yylloc.filename = filename = copy_string(file_path.c_str());

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
		reporter->Error("@else without @if...");

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
		reporter->Error("unbalanced @if... @endif");

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

void add_input_file(const char* file)
	{
	if ( ! file )
		reporter->InternalError("empty filename");

	if ( ! filename )
		(void) load_files(file);
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
	if ( reporter->Errors() > 0 )
		return 1;

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
		if ( load_files(input_files[0]) )
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

	// For each file scanned so far, and for each @prefix, look for a
	// prefixed and flattened version of the loaded file in BROPATH. The
	// flattening involves taking the path in BROPATH in which the
	// scanned file lives and replacing '/' path separators with a '.' If
	// the scanned file is "__load__.bro", that part of the flattened
	// file name is discarded. If the prefix is non-empty, it gets placed
	// in front of the flattened path, separated with another '.'
	std::list<ScannedFile>::iterator it;
	bool found_prefixed_files = false;
	for ( it = files_scanned.begin(); it != files_scanned.end(); ++it )
		{
		if ( it->skipped || it->prefixes_checked )
			continue;

		it->prefixes_checked = true;
		// Prefixes are pushed onto a stack, so iterate backwards.
		for ( int i = prefixes.length() - 1; i >= 0; --i )
			{
			// Don't look at empty prefixes.
			if ( ! prefixes[i][0] )
				continue;

			string canon = without_bropath_component(it->name);
			string flat = flatten_script_name(canon, prefixes[i]);
			string path = find_relative_file(flat, "bro");

			if ( ! path.empty() )
				{
				add_input_file(path.c_str());
				found_prefixed_files = true;
				}

			//printf("====== prefix search ======\n");
			//printf("File  : %s\n", it->name.c_str());
			//printf("Canon : %s\n", canon.c_str());
			//printf("Flat  : %s\n", flat.c_str());
			//printf("Found : %s\n", path.empty() ? "F" : "T");
			//printf("===========================\n");
			}
		}

	if ( found_prefixed_files )
		return 0;

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
	}

FileInfo::~FileInfo()
	{
	if ( yyin && yyin != stdin )
		fclose(yyin);

	yy_switch_to_buffer(buffer_state);
	yylloc.filename = filename = name;
	yylloc.first_line = yylloc.last_line = line_number = line;

	if ( restore_module != "" )
		current_module = restore_module;
	}
