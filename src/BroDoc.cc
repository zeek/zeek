#include <cstdio>
#include <cstdarg>
#include <string>
#include <list>
#include <algorithm>
#include <libgen.h>

#include "BroDoc.h"
#include "BroDocObj.h"
#include "util.h"
#include "plugin/Manager.h"
#include "analyzer/Manager.h"
#include "analyzer/Component.h"
#include "file_analysis/Manager.h"

BroDoc::BroDoc(const std::string& rel, const std::string& abs)
	{
	size_t f_pos = abs.find_last_of('/');

	if ( std::string::npos == f_pos )
		source_filename = abs;
	else
		source_filename = abs.substr(f_pos + 1);

	if ( rel[0] == '/' || rel[0] == '.' )
		{
		// The Bro script isn't being loaded via BROPATH, so just use basename
		// as the document title.
		doc_title = source_filename;
		}
	else
		{
		// Keep the relative directory as part of the document title.
		if ( rel.size() == 0 || rel[rel.size() - 1] == '/' )
			doc_title = rel + source_filename;
		else
			doc_title = rel + "/" + source_filename;
		}

	downloadable_filename = source_filename;

#if 0
	size_t ext_pos = downloadable_filename.find(".bif.bro");
	if ( std::string::npos != ext_pos )
		downloadable_filename.erase(ext_pos + 4);
#endif

	reST_filename = doc_title;
	size_t ext_pos = reST_filename.find(".bro");

	if ( std::string::npos == ext_pos )
		reST_filename += ".rst";
	else
		reST_filename.replace(ext_pos, 4, ".rst");

	reST_filename = doc_title.substr(0, ext_pos);
	reST_filename += ".rst";

	// Instead of re-creating the directory hierarchy based on related
	// loads, just replace the directory separatories such that the reST
	// output will all be placed in a flat directory (the working dir).
	std::for_each(reST_filename.begin(), reST_filename.end(), replace_slash());

	reST_file = fopen(reST_filename.c_str(), "w");

	if ( ! reST_file )
		fprintf(stderr, "Failed to open %s\n", reST_filename.c_str());

#ifdef DOCDEBUG
	fprintf(stdout, "Documenting absolute source: %s\n", abs.c_str());
	fprintf(stdout, "\trelative dir: %s\n", rel.c_str());
	fprintf(stdout, "\tdoc title: %s\n", doc_title.c_str());
	fprintf(stdout, "\tbro file: %s\n", source_filename.c_str());
	fprintf(stdout, "\trst file: %s\n", reST_filename.c_str());
#endif
	}

BroDoc::~BroDoc()
	{
	if ( reST_file && fclose( reST_file ) )
		fprintf(stderr, "Failed to close %s\n", reST_filename.c_str());

	FreeBroDocObjPtrList(all);
	}

void BroDoc::AddImport(const std::string& s)
	{
	std::string lname(s);
	// First strip any .bro extension.
	size_t ext_pos = lname.find(".bro");
	if ( ext_pos != std::string::npos )
		lname = lname.substr(0, ext_pos);

	const char* full_filename = NULL;
	const char* subpath = NULL;

	FILE* f = search_for_file(lname.c_str(), "bro", &full_filename, true,
	                          &subpath);

	if ( f && full_filename && subpath )
		{
		char* tmp = copy_string(full_filename);
		char* filename = basename(tmp);
		extern char* PACKAGE_LOADER;

		if ( streq(filename, PACKAGE_LOADER) )
			{
			// link to the package's index
			string pkg(subpath);
			pkg += "/index";
			imports.push_back(pkg);
			}
		else
			{
			if ( subpath[0] == '/' || subpath[0] == '.' )
				{
				// it's not a subpath of scripts/, so just add the name of it
				// as it's given in the @load directive
				imports.push_back(lname);
				}
			else
				{
				// combine the base file name of script in the @load directive
				// with the subpath of BROPATH's scripts/ directory
				string fname(subpath);
				char* othertmp = copy_string(lname.c_str());
				fname.append("/").append(basename(othertmp));
				imports.push_back(fname);
				delete [] othertmp;
				}
			}

		delete [] tmp;
		}

	else
		fprintf(stderr, "Failed to document '@load %s' in file: %s\n",
		        s.c_str(), reST_filename.c_str());

	if ( f )
		fclose(f);

	delete [] full_filename;
	delete [] subpath;
	}

void BroDoc::SetPacketFilter(const std::string& s)
	{
	packet_filter = s;
	size_t pos1 = s.find("{\n");
	size_t pos2 = s.find("}");

	if ( pos1 != std::string::npos && pos2 != std::string::npos )
		packet_filter = s.substr(pos1 + 2, pos2 - 2);

	bool has_non_whitespace = false;

	for ( std::string::const_iterator it = packet_filter.begin();
		it != packet_filter.end(); ++it )
		{
		if ( *it != ' ' && *it != '\t' && *it != '\n' && *it != '\r' )
			{
			has_non_whitespace = true;
			break;
			}
		}

	if ( ! has_non_whitespace )
		packet_filter.clear();
	}

void BroDoc::WriteDocFile() const
	{
	WriteToDoc(reST_file, ".. Automatically generated.  Do not edit.\n\n");

	WriteToDoc(reST_file, ":tocdepth: 3\n\n");

	WriteSectionHeading(reST_file, doc_title.c_str(), '=');

	WriteStringList(reST_file, ".. bro:namespace:: %s\n", modules);

	WriteToDoc(reST_file, "\n");

	// WriteSectionHeading(reST_file, "Overview", '-');
	WriteStringList(reST_file, "%s\n", summary);

	WriteToDoc(reST_file, "\n");

	if ( ! modules.empty() )
		{
		WriteToDoc(reST_file, ":Namespace%s: ", (modules.size() > 1 ? "s" : ""));
		// WriteStringList(reST_file, ":bro:namespace:`%s`", modules);
		WriteStringList(reST_file, "``%s``, ", "``%s``", modules);
		WriteToDoc(reST_file, "\n");
		}

	if ( ! imports.empty() )
		{
		WriteToDoc(reST_file, ":Imports: ");
		std::list<std::string>::const_iterator it;
		for ( it = imports.begin(); it != imports.end(); ++it )
			{
			if ( it != imports.begin() )
				WriteToDoc(reST_file, ", ");

			string pretty(*it);
			size_t pos = pretty.find("/index");
			if ( pos != std::string::npos && pos + 6 == pretty.size() )
				pretty = pretty.substr(0, pos);
			WriteToDoc(reST_file, ":doc:`%s </scripts/%s>`", pretty.c_str(), it->c_str());
			}
		WriteToDoc(reST_file, "\n");
		}

	WriteToDoc(reST_file, ":Source File: :download:`%s`\n",
		downloadable_filename.c_str());

	WriteToDoc(reST_file, "\n");

	WriteInterface("Summary", '~', '#', true, true);

	if ( ! notices.empty() )
		WriteBroDocObjList(reST_file, notices, "Notices", '#');

	if ( port_analysis.size() || packet_filter.size() )
		WriteSectionHeading(reST_file, "Configuration Changes", '#');

	if ( ! port_analysis.empty() )
		{
		WriteSectionHeading(reST_file, "Port Analysis", '^');
		WriteToDoc(reST_file, "Loading this script makes the following changes to "
		           ":bro:see:`dpd_config`.\n\n");
		WriteStringList(reST_file, "%s, ", "%s", port_analysis);
		}

	if ( ! packet_filter.empty() )
		{
		WriteSectionHeading(reST_file, "Packet Filter", '^');
		WriteToDoc(reST_file, "Loading this script makes the following changes to "
		           ":bro:see:`capture_filters`.\n\n");
		WriteToDoc(reST_file, "Filters added::\n\n");
		WriteToDoc(reST_file, "%s\n", packet_filter.c_str());
		}

	WriteInterface("Detailed Interface", '~', '#', true, false);

#if 0   // Disabled for now.
	BroDocObjList::const_iterator it;
	bool hasPrivateIdentifiers = false;

	for ( it = all.begin(); it != all.end(); ++it )
		{
		if ( ! IsPublicAPI(*it) )
			{
			hasPrivateIdentifiers = true;
			break;
			}
		}

	if ( hasPrivateIdentifiers )
		WriteInterface("Private Interface", '~', '#', false, false);
#endif
	}

void BroDoc::WriteInterface(const char* heading, char underline,
			char sub, bool isPublic, bool isShort) const
	{
	WriteSectionHeading(reST_file, heading, underline);
	WriteBroDocObjList(reST_file, options, isPublic, "Options", sub, isShort);
	WriteBroDocObjList(reST_file, constants, isPublic, "Constants", sub, isShort);
	WriteBroDocObjList(reST_file, state_vars, isPublic, "State Variables", sub, isShort);
	WriteBroDocObjList(reST_file, types, isPublic, "Types", sub, isShort);
	WriteBroDocObjList(reST_file, events, isPublic, "Events", sub, isShort);
	WriteBroDocObjList(reST_file, hooks, isPublic, "Hooks", sub, isShort);
	WriteBroDocObjList(reST_file, functions, isPublic, "Functions", sub, isShort);
	WriteBroDocObjList(reST_file, redefs, isPublic, "Redefinitions", sub, isShort);
	}

void BroDoc::WriteStringList(FILE* f, const char* format, const char* last_format,
			const std::list<std::string>& l)
	{
	if ( l.empty() )
		{
		WriteToDoc(f, "\n");
		return;
		}

	std::list<std::string>::const_iterator it;
	std::list<std::string>::const_iterator last = l.end();
	last--;

	for ( it = l.begin(); it != last; ++it )
		WriteToDoc(f, format, it->c_str());

	WriteToDoc(f, last_format, last->c_str());
	}

void BroDoc::WriteBroDocObjTable(FILE* f, const BroDocObjList& l)
	{
	int max_id_col = 0;
	int max_com_col = 0;
	BroDocObjList::const_iterator it;

	for ( it = l.begin(); it != l.end(); ++it )
		{
		int c = (*it)->ColumnSize();

		if ( c > max_id_col )
			max_id_col = c;

		c = (*it)->LongestShortDescLen();

		if ( c > max_com_col )
			max_com_col = c;
		}

	// Start table.
	WriteRepeatedChar(f, '=', max_id_col);
	WriteToDoc(f, " ");

	if ( max_com_col == 0 )
		WriteToDoc(f, "=");
	else
		WriteRepeatedChar(f, '=', max_com_col);

	WriteToDoc(f, "\n");

	for ( it = l.begin(); it != l.end(); ++it )
		{
		if ( it != l.begin() )
			WriteToDoc(f, "\n\n");
		(*it)->WriteReSTCompact(f, max_id_col);
		}

	// End table.
	WriteToDoc(f, "\n");
	WriteRepeatedChar(f, '=', max_id_col);
	WriteToDoc(f, " ");

	if ( max_com_col == 0 )
		WriteToDoc(f, "=");
	else
		WriteRepeatedChar(f, '=', max_com_col);

	WriteToDoc(f, "\n\n");
	}

void BroDoc::WriteBroDocObjList(FILE* f, const BroDocObjList& l, bool wantPublic,
			const char* heading, char underline, bool isShort)
	{
	if ( l.empty() )
		return;

	BroDocObjList::const_iterator it;
	bool (*f_ptr)(const BroDocObj* o) = 0;

	if ( wantPublic )
		f_ptr = IsPublicAPI;
	else
		f_ptr = IsPrivateAPI;

	it = std::find_if(l.begin(), l.end(), f_ptr);

	if ( it == l.end() )
		return;

	WriteSectionHeading(f, heading, underline);

	BroDocObjList filtered_list;

	while ( it != l.end() )
		{
		filtered_list.push_back(*it);
		it = find_if(++it, l.end(), f_ptr);
		}

	if ( isShort )
		WriteBroDocObjTable(f, filtered_list);
	else
		WriteBroDocObjList(f, filtered_list);
	}

void BroDoc::WriteBroDocObjList(FILE* f, const BroDocObjMap& m, bool wantPublic,
			const char* heading, char underline, bool isShort)
	{
	BroDocObjMap::const_iterator it;
	BroDocObjList l;

	for ( it = m.begin(); it != m.end(); ++it )
		l.push_back(it->second);

	WriteBroDocObjList(f, l, wantPublic, heading, underline, isShort);
	}

void BroDoc::WriteBroDocObjList(FILE* f, const BroDocObjList& l, const char* heading,
			char underline)
	{
	WriteSectionHeading(f, heading, underline);
	WriteBroDocObjList(f, l);
	}

void BroDoc::WriteBroDocObjList(FILE* f, const BroDocObjList& l)
	{
	for ( BroDocObjList::const_iterator it = l.begin(); it != l.end(); ++it )
		(*it)->WriteReST(f);
	}

void BroDoc::WriteBroDocObjList(FILE* f, const BroDocObjMap& m, const char* heading,
			char underline)
	{
	BroDocObjMap::const_iterator it;
	BroDocObjList l;

	for ( it = m.begin(); it != m.end(); ++it )
		l.push_back(it->second);

	WriteBroDocObjList(f, l, heading, underline);
	}

void BroDoc::WriteToDoc(FILE* f, const char* format, ...)
	{
	va_list argp;
	va_start(argp, format);
	vfprintf(f, format, argp);
	va_end(argp);
	}

void BroDoc::WriteSectionHeading(FILE* f, const char* heading, char underline)
	{
	WriteToDoc(f, "%s\n", heading);
	WriteRepeatedChar(f, underline, strlen(heading));
	WriteToDoc(f, "\n");
	}

void BroDoc::WriteRepeatedChar(FILE* f, char c, size_t n)
	{
	for ( size_t i = 0; i < n; ++i )
		WriteToDoc(f, "%c", c);
	}

void BroDoc::FreeBroDocObjPtrList(BroDocObjList& l)
	{
	for ( BroDocObjList::const_iterator it = l.begin(); it != l.end(); ++it )
		delete *it;

	l.clear();
	}

void BroDoc::AddFunction(BroDocObj* o)
	{
	BroDocObjMap::const_iterator it = functions.find(o->Name());
	if ( it == functions.end() )
		{
		functions[o->Name()] = o;
		all.push_back(o);
		}
	else
		functions[o->Name()]->Combine(o);
	}

static void WritePluginSectionHeading(FILE* f, const plugin::Plugin* p)
	{
	string name = p->Name();

	fprintf(f, "%s\n", name.c_str());
	for ( size_t i = 0; i < name.size(); ++i )
		fprintf(f, "-");
	fprintf(f, "\n\n");

	fprintf(f, "%s\n\n", p->Description());
	}

static void WriteAnalyzerComponent(FILE* f, const analyzer::Component* c)
	{
	EnumType* atag = analyzer_mgr->GetTagEnumType();
	string tag = fmt("ANALYZER_%s", c->CanonicalName());

	if ( atag->Lookup("Analyzer", tag.c_str()) < 0 )
		reporter->InternalError("missing analyzer tag for %s", tag.c_str());

	fprintf(f, ":bro:enum:`Analyzer::%s`\n\n", tag.c_str());
	}

static void WriteAnalyzerComponent(FILE* f, const file_analysis::Component* c)
	{
	EnumType* atag = file_mgr->GetTagEnumType();
	string tag = fmt("ANALYZER_%s", c->CanonicalName());

	if ( atag->Lookup("Files", tag.c_str()) < 0 )
		reporter->InternalError("missing analyzer tag for %s", tag.c_str());

	fprintf(f, ":bro:enum:`Files::%s`\n\n", tag.c_str());
	}

static void WritePluginComponents(FILE* f, const plugin::Plugin* p)
	{
	plugin::Plugin::component_list components = p->Components();
	plugin::Plugin::component_list::const_iterator it;

	fprintf(f, "Components\n");
	fprintf(f, "++++++++++\n\n");

	for ( it = components.begin(); it != components.end(); ++it )
		{
		switch ( (*it)->Type() ) {
		case plugin::component::ANALYZER:
			{
			const analyzer::Component* c =
			        dynamic_cast<const analyzer::Component*>(*it);

			if ( c )
				WriteAnalyzerComponent(f, c);
			else
				reporter->InternalError("component type mismatch");
			}
			break;

		case plugin::component::FILE_ANALYZER:
			{
			const file_analysis::Component* c =
			        dynamic_cast<const file_analysis::Component*>(*it);

			if ( c )
				WriteAnalyzerComponent(f, c);
			else
				reporter->InternalError("component type mismatch");
			}
			break;

		case plugin::component::READER:
			reporter->InternalError("docs for READER component unimplemented");

		case plugin::component::WRITER:
			reporter->InternalError("docs for WRITER component unimplemented");

		default:
			reporter->InternalError("docs for unknown component unimplemented");
		}
		}
	}

static void WritePluginBifItems(FILE* f, const plugin::Plugin* p,
                                plugin::BifItem::Type t, const string& heading)
	{
	plugin::Plugin::bif_item_list bifitems = p->BifItems();
	plugin::Plugin::bif_item_list::iterator it = bifitems.begin();

	while ( it != bifitems.end() )
		{
		if ( it->GetType() != t )
			it = bifitems.erase(it);
		else
			++it;
		}

	if ( bifitems.empty() )
		return;

	fprintf(f, "%s\n", heading.c_str());
	for ( size_t i = 0; i < heading.size(); ++i )
		fprintf(f, "+");
	fprintf(f, "\n\n");

	for ( it = bifitems.begin(); it != bifitems.end(); ++it )
		{
		BroDocObj* o = doc_ids[it->GetID()];

		if ( o )
			o->WriteReST(f);
		else
			reporter->Warning("No docs for ID: %s\n", it->GetID());
		}
	}

static void WriteAnalyzerTagDefn(FILE* f, EnumType* e, const string& module)
	{
	string tag_id= module + "::Tag";
	e = new CommentedEnumType(e);
	e->SetTypeID(copy_string(tag_id.c_str()));

	ID* dummy_id = new ID(tag_id.c_str(), SCOPE_GLOBAL, true);
	dummy_id->SetType(e);
	dummy_id->MakeType();

	list<string>* r = new list<string>();
	r->push_back("Unique identifiers for analyzers.");

	BroDocObj bdo(dummy_id, r, true);

	bdo.WriteReST(f);
	}

static bool ComponentsMatch(const plugin::Plugin* p, plugin::component::Type t,
                            bool match_empty = false)
	{
	plugin::Plugin::component_list components = p->Components();
	plugin::Plugin::component_list::const_iterator it;

	if ( components.empty() )
		return match_empty;

	for ( it = components.begin(); it != components.end(); ++it )
		if ( (*it)->Type() != t )
			return false;

	return true;
	}

void CreateProtoAnalyzerDoc(const char* filename)
	{
	FILE* f = fopen(filename, "w");

	fprintf(f, "Protocol Analyzers\n");
	fprintf(f, "==================\n\n\n");
	fprintf(f, ".. contents::\n");
	fprintf(f, "     :depth: 1\n\n");

	WriteAnalyzerTagDefn(f, analyzer_mgr->GetTagEnumType(), "Analyzer");

	plugin::Manager::plugin_list plugins = plugin_mgr->Plugins();
	plugin::Manager::plugin_list::const_iterator it;

	for ( it = plugins.begin(); it != plugins.end(); ++it )
		{
		if ( ! ComponentsMatch(*it, plugin::component::ANALYZER, true) )
			continue;

		WritePluginSectionHeading(f, *it);
		WritePluginComponents(f, *it);
		WritePluginBifItems(f, *it, plugin::BifItem::CONSTANT,
		                    "Options/Constants");
		WritePluginBifItems(f, *it, plugin::BifItem::GLOBAL, "Globals");
		WritePluginBifItems(f, *it, plugin::BifItem::TYPE, "Types");
		WritePluginBifItems(f, *it, plugin::BifItem::EVENT, "Events");
		WritePluginBifItems(f, *it, plugin::BifItem::FUNCTION, "Functions");
		}

	fclose(f);
	}

void CreateFileAnalyzerDoc(const char* filename)
	{
	FILE* f = fopen(filename, "w");

	fprintf(f, "File Analyzers\n");
	fprintf(f, "==============\n\n");
	fprintf(f, ".. contents::\n");
	fprintf(f, "     :depth: 1\n\n");

	WriteAnalyzerTagDefn(f, file_mgr->GetTagEnumType(), "Files");

	plugin::Manager::plugin_list plugins = plugin_mgr->Plugins();
	plugin::Manager::plugin_list::const_iterator it;

	for ( it = plugins.begin(); it != plugins.end(); ++it )
		{
		if ( ! ComponentsMatch(*it, plugin::component::FILE_ANALYZER) )
			continue;

		WritePluginSectionHeading(f, *it);
		WritePluginComponents(f, *it);
		WritePluginBifItems(f, *it, plugin::BifItem::CONSTANT,
		                    "Options/Constants");
		WritePluginBifItems(f, *it, plugin::BifItem::GLOBAL, "Globals");
		WritePluginBifItems(f, *it, plugin::BifItem::TYPE, "Types");
		WritePluginBifItems(f, *it, plugin::BifItem::EVENT, "Events");
		WritePluginBifItems(f, *it, plugin::BifItem::FUNCTION, "Functions");
		}

	fclose(f);
	}
