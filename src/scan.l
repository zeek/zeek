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
#include "BroDoc.h"
#include "Reporter.h"
#include "RE.h"
#include "Net.h"

#include "analyzer/Analyzer.h"

extern YYLTYPE yylloc;	// holds start line and column of token
extern int print_loaded_scripts;
extern int generate_documentation;

// Track the @if... depth.
ptr_compat_int current_depth = 0;

int_list if_stack;

int line_number = 1;
const char* filename = 0;
BroDoc* current_reST_doc = 0;
static BroDoc* last_reST_doc = 0;
string current_scanned_file_path;

char last_tok[128];

#define YY_USER_ACTION	strncpy(last_tok, yytext, sizeof(last_tok) - 1);
#define YY_USER_INIT	last_tok[0] = '\0';

// We define our own YY_INPUT because we want to trap the case where
// a read fails.
#define YY_INPUT(buf,result,max_size) \
	if ( ((result = fread(buf, 1, max_size, yyin)) == 0) && ferror(yyin) ) \
		reporter->Error("read failed with \"%s\"", strerror(errno));

// reST documents that we've created (or have at least opened so far).
std::list<BroDoc*> docs_generated;

// reST comments (those starting with ##) seen so far.
std::list<std::string>* reST_doc_comments = 0;

// Print current contents of reST_doc_comments list to stderr.
void print_current_reST_doc_comments();

// Delete the reST_doc_comments list object.
void clear_reST_doc_comments();

// Adds changes to capture_filter to the current script's reST documentation.
static void check_capture_filter_changes();

static const char* canon_doc_comment(const char* comment)
	{
	// "##Text" and "## Text" are treated the same in order to be able
	// to still preserve indentation level, but not unintentionally
	// signify an indentation level for all the text when using
	// the "## Text" style.
	return ( comment[0] == ' ' ) ? comment + 1 : comment;
	}

static std::string canon_doc_func_param(const char* id_start)
	{
	std::string id_name(id_start, strcspn(id_start, ":"));
	const char* comment = id_start + id_name.size() + 1;
	std::string doc;

	if ( id_name == "Returns" )
		doc.append(":returns:").append(comment);
	else
		doc.append(":param ").append(id_name).append(":").append(comment);
	return doc;
	}

static ino_t get_inode_num(FILE* f, const char* filename)
	{
	struct stat b;

	if ( fstat(fileno(f), &b) )
		{
		reporter->Error("failed to fstat fd of %s\n", filename);
		exit(1);
		}

	return b.st_ino;
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
	BroDoc* doc;
	string path;
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
%s DOC

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
	// Add this format of comments to the script documentation's "summary".
	if ( generate_documentation )
		current_reST_doc->AddSummary(canon_doc_comment(yytext + 3));
	}

<DOC>##<.* {
	yylval.str = copy_string(canon_doc_comment(yytext + 3));
	return TOK_POST_DOC;
}

<DOC>##{OWS}{ID}:{WS}.* {
	const char* id_start = skip_whitespace(yytext + 2);
	yylval.str = copy_string(canon_doc_func_param(id_start).c_str());
	return TOK_DOC;
}

<DOC>##.* {
	if ( yytext[2] != '#' )
		{
		yylval.str = copy_string(canon_doc_comment(yytext + 2));
		return TOK_DOC;
		}
}

##{OWS}{ID}:{WS}.* {
	if ( generate_documentation )
		{
		// Comment is documenting either a function parameter or return type,
		// so appropriate reST markup substitutions are automatically made
		// in order to distinguish them from other comments.
		if ( ! reST_doc_comments )
			reST_doc_comments = new std::list<std::string>();

		// always insert a blank line so that this param/return markup
		// 1) doesn't show up in the summary section in the case that it's
		//    the first comment for the function/event
		// 2) has a blank line between it and non-field-list reST markup,
		//    which is required for correct HTML rendering by Sphinx
		reST_doc_comments->push_back("");
		const char* id_start = skip_whitespace(yytext + 2);
		reST_doc_comments->push_back(canon_doc_func_param(id_start));
		}
}

##<.* {
	if ( generate_documentation && BroDocObj::last )
		BroDocObj::last->AddDocString(canon_doc_comment(yytext + 3));
}

##.* {
	if ( generate_documentation && (yytext[2] != '#') )
		{
		if ( ! reST_doc_comments )
			reST_doc_comments = new std::list<std::string>();

		reST_doc_comments->push_back(canon_doc_comment(yytext + 2));
		}
}

#{OWS}@no-test.* return TOK_NO_TEST;

#.*	/* eat comments */

{WS}	/* eat whitespace */

<INITIAL,IGNORE,DOC>\n	{
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
	string rval = current_scanned_file_path;

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
	char* filename_copy = copy_string(::filename);
	const char* bname = basename(filename_copy);

	if ( ! bname )
		reporter->InternalError("basename failed: %s", strerror(errno));

	StringVal* rval = new StringVal(bname);
	delete [] filename_copy;
	RET_CONST(rval);
	}

@load{WS}{FILE}	{
	const char* new_file = skip_whitespace(yytext + 5);	// Skip "@load".
	if ( generate_documentation )
		{
		current_reST_doc->AddImport(new_file);

		if ( reST_doc_comments )
			{
			fprintf(stderr, "Warning: unconsumed reST documentation is being "
					"discarded before doing '@load %s' in %s:\n",
					 new_file, current_reST_doc->GetSourceFileName());
			clear_reST_doc_comments();
			}
		}
	(void) load_files(new_file);
	}

@load-sigs{WS}{FILE} {
	const char* new_sig_file = skip_whitespace(yytext + 10);
	const char* full_filename = 0;
	FILE* f = search_for_file(new_sig_file, "sig", &full_filename, false, 0);

	if ( f )
		{
		sig_files.push_back(full_filename);
		fclose(f);
		delete [] full_filename;
		}
	else
		reporter->Error("failed to find file associated with @load-sigs %s",
		                new_sig_file);
	}

@unload{WS}{FILE}	{
	// Skip "@unload".
	const char* new_file = skip_whitespace(yytext + 7);

	// All we have to do is pretend we've already scanned it.
	const char* full_filename;
	FILE* f = search_for_file(new_file, "bro", &full_filename, true, 0);

	if ( f )
		{
		ScannedFile sf(get_inode_num(f, full_filename), file_stack.length(), full_filename, "", true);
		files_scanned.push_back(sf);

		fclose(f);
		delete [] full_filename;
		}

	else
		reporter->Error("failed find file associated with @unload %s", new_file);
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

static int load_files(const char* orig_file)
	{
	// Whether we pushed on a FileInfo that will restore the
	// current module after the final file has been scanned.
	bool did_module_restore = false;

	const char* full_filename = "<internal error>";
	const char* bropath_subpath = "<internal error>";
	const char* bropath_subpath_delete = 0;
	FILE* f;

	if ( streq(orig_file, "-") )
		{
		f = stdin;
		full_filename = "<stdin>";
		bropath_subpath = "";

		if ( g_policy_debug )
			{
			debug_msg("Warning: can't use debugger while reading policy from stdin; turning off debugging.\n");
			g_policy_debug = false;
			}
		}

	else
		{
		f = search_for_file(orig_file, "bro", &full_filename, true, &bropath_subpath);
		bropath_subpath_delete = bropath_subpath; // This will be deleted.
		}

	if ( f )
		{
		ino_t i = get_inode_num(f, full_filename);
		std::list<ScannedFile>::const_iterator it;

		for ( it = files_scanned.begin(); it != files_scanned.end(); ++it )
			{
			if ( it->inode == i )
				{
				if ( f != stdin )
					{
					fclose(f);
					delete [] full_filename;
					delete [] bropath_subpath_delete;
					}
				return 0;
				}
			}

		ScannedFile sf(i, file_stack.length(), full_filename, bropath_subpath);
		files_scanned.push_back(sf);

		if ( g_policy_debug )
			{
			// Add the filename to the file mapping
			// table (Debug.h).
			Filemap* map = new Filemap;

			// Make sure it wasn't already read in.
			HashKey* key = new HashKey(full_filename);
			if ( g_dbgfilemaps.Lookup(key) )
				{
				// reporter->Warning("Not re-reading policy file; check BRO_PREFIXES:", full_filename);
				fclose(f);
				delete key;
				return 0;
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

		char* tmp = copy_string(full_filename);
		current_scanned_file_path = dirname(tmp);
		delete [] tmp;

		if ( generate_documentation )
			{
			current_reST_doc = new BroDoc(bropath_subpath, full_filename);
			docs_generated.push_back(current_reST_doc);
			}

		delete [] bropath_subpath_delete;

		// "orig_file", could be an alias for yytext, which is ephemeral
		//  and will be zapped after the yy_switch_to_buffer() below.
		yy_switch_to_buffer(yy_create_buffer(f, YY_BUF_SIZE));

		yylloc.first_line = yylloc.last_line = line_number = 1;

		// Don't delete the old filename - it's pointed to by
		// every BroObj created when parsing it.
		yylloc.filename = filename = full_filename;
		}

	else
		{
		reporter->Error("can't open %s", full_filename);
		exit(1);
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

void do_doc_token_start()
	{
	if ( generate_documentation )
	    BEGIN(DOC);
	}

void do_doc_token_stop()
	{
	if ( generate_documentation )
	    BEGIN(INITIAL);
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
		check_capture_filter_changes();

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

	check_capture_filter_changes();

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

			string s;
			s = dot_canon(it->subpath.c_str(), it->name.c_str(), prefixes[i]);
			FILE* f = search_for_file(s.c_str(), "bro", 0, false, 0);

			//printf("====== prefix search ======\n");
			//printf("File  : %s\n", it->name.c_str());
			//printf("Path  : %s\n", it->subpath.c_str());
			//printf("Dotted: %s\n", s.c_str());
			//printf("Found : %s\n", f ? "T" : "F");
			//printf("===========================\n");

			if ( f )
				{
				add_input_file(s.c_str());
				found_prefixed_files = true;
				fclose(f);
				}
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

	if ( generate_documentation )
		clear_reST_doc_comments();

	// Otherwise, we are done.
	return 1;
	}

FileInfo::FileInfo(string arg_restore_module)
	{
	buffer_state = YY_CURRENT_BUFFER;
	restore_module = arg_restore_module;
	name = ::filename;
	line = ::line_number;
	doc = ::current_reST_doc;
	path = current_scanned_file_path;
	}

FileInfo::~FileInfo()
	{
	if ( yyin && yyin != stdin )
		fclose(yyin);

	yy_switch_to_buffer(buffer_state);
	yylloc.filename = filename = name;
	yylloc.first_line = yylloc.last_line = line_number = line;
	last_reST_doc = current_reST_doc;
	current_reST_doc = doc;
	current_scanned_file_path = path;

	if ( restore_module != "" )
		current_module = restore_module;
	}

static void check_capture_filter_changes()
	{
	if ( ! generate_documentation )
	    return;

	// Lookup the "capture_filters" identifier, if it has any defined
	// value, add it to the script's reST documentation, and finally
	// clear the table so it doesn't taint the documentation for
	// subsequent scripts.

	ID* capture_filters = global_scope()->Lookup("capture_filters");

	if ( capture_filters )
		{
		ODesc desc;
		desc.SetIndentSpaces(4);
		capture_filters->ID_Val()->Describe(&desc);
		last_reST_doc->SetPacketFilter(desc.Description());
		capture_filters->ID_Val()->AsTableVal()->RemoveAll();
		}
	}

void print_current_reST_doc_comments()
	{
	if ( ! reST_doc_comments )
		return;

	std::list<std::string>::iterator it;

	for ( it = reST_doc_comments->begin(); it != reST_doc_comments->end(); ++it )
		fprintf(stderr, "##%s\n", it->c_str());
	}

void clear_reST_doc_comments()
	{
	if ( ! reST_doc_comments )
		return;

	fprintf(stderr, "Warning: %zu unconsumed reST comments:\n",
			reST_doc_comments->size());

	print_current_reST_doc_comments();
	delete reST_doc_comments;
	reST_doc_comments = 0;
	}
