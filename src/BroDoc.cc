#include <cstdio>
#include <cstdarg>
#include <string>
#include <list>
#include <algorithm>
#include <libgen.h>

#include "BroDoc.h"
#include "BroDocObj.h"
#include "util.h"

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

	size_t ext_pos = downloadable_filename.find(".bif.bro");
	if ( std::string::npos != ext_pos )
		downloadable_filename.erase(ext_pos + 4);

	reST_filename = doc_title;
	ext_pos = reST_filename.find(".bro");

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
		fclose(f);

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

void BroDoc::AddPortAnalysis(const std::string& analyzer,
			const std::string& ports)
	{
	std::string reST_string = analyzer + "::\n" + ports + "\n\n";
	port_analysis.push_back(reST_string);
	}

void BroDoc::WriteDocFile() const
	{
	WriteToDoc(".. Automatically generated.  Do not edit.\n\n");

	WriteToDoc(":tocdepth: 3\n\n");

	WriteSectionHeading(doc_title.c_str(), '=');

	WriteStringList(".. bro:namespace:: %s\n", modules);

	WriteToDoc("\n");

	// WriteSectionHeading("Overview", '-');
	WriteStringList("%s\n", summary);

	WriteToDoc("\n");

	if ( ! modules.empty() )
		{
		WriteToDoc(":Namespace%s: ", (modules.size() > 1 ? "s" : ""));
		// WriteStringList(":bro:namespace:`%s`", modules);
		WriteStringList("``%s``, ", "``%s``", modules);
		WriteToDoc("\n");
		}

	if ( ! imports.empty() )
		{
		WriteToDoc(":Imports: ");
		std::list<std::string>::const_iterator it;
		for ( it = imports.begin(); it != imports.end(); ++it )
			{
			if ( it != imports.begin() )
				WriteToDoc(", ");

			string pretty(*it);
			size_t pos = pretty.find("/index");
			if ( pos != std::string::npos && pos + 6 == pretty.size() )
				pretty = pretty.substr(0, pos);
			WriteToDoc(":doc:`%s </scripts/%s>`", pretty.c_str(), it->c_str());
			}
		WriteToDoc("\n");
		}

	WriteToDoc(":Source File: :download:`%s`\n",
		downloadable_filename.c_str());

	WriteToDoc("\n");

	WriteInterface("Summary", '~', '#', true, true);

	if ( ! notices.empty() )
		WriteBroDocObjList(notices, "Notices", '#');

	if ( port_analysis.size() || packet_filter.size() )
		WriteSectionHeading("Configuration Changes", '#');

	if ( ! port_analysis.empty() )
		{
		WriteSectionHeading("Port Analysis", '^');
		WriteToDoc("Loading this script makes the following changes to "
		           ":bro:see:`dpd_config`.\n\n");
		WriteStringList("%s, ", "%s", port_analysis);
		}

	if ( ! packet_filter.empty() )
		{
		WriteSectionHeading("Packet Filter", '^');
		WriteToDoc("Loading this script makes the following changes to "
		           ":bro:see:`capture_filters`.\n\n");
		WriteToDoc("Filters added::\n\n");
		WriteToDoc("%s\n", packet_filter.c_str());
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
	WriteSectionHeading(heading, underline);
	WriteBroDocObjList(options, isPublic, "Options", sub, isShort);
	WriteBroDocObjList(constants, isPublic, "Constants", sub, isShort);
	WriteBroDocObjList(state_vars, isPublic, "State Variables", sub, isShort);
	WriteBroDocObjList(types, isPublic, "Types", sub, isShort);
	WriteBroDocObjList(events, isPublic, "Events", sub, isShort);
	WriteBroDocObjList(functions, isPublic, "Functions", sub, isShort);
	WriteBroDocObjList(redefs, isPublic, "Redefinitions", sub, isShort);
	}

void BroDoc::WriteStringList(const char* format, const char* last_format,
			const std::list<std::string>& l) const
	{
	if ( l.empty() )
		{
		WriteToDoc("\n");
		return;
		}

	std::list<std::string>::const_iterator it;
	std::list<std::string>::const_iterator last = l.end();
	last--;

	for ( it = l.begin(); it != last; ++it )
		WriteToDoc(format, it->c_str());

	WriteToDoc(last_format, last->c_str());
	}

void BroDoc::WriteBroDocObjTable(const BroDocObjList& l) const
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
	WriteRepeatedChar('=', max_id_col);
	WriteToDoc(" ");

	if ( max_com_col == 0 )
		WriteToDoc("=");
	else
		WriteRepeatedChar('=', max_com_col);

	WriteToDoc("\n");

	for ( it = l.begin(); it != l.end(); ++it )
		{
		if ( it != l.begin() )
			WriteToDoc("\n\n");
		(*it)->WriteReSTCompact(reST_file, max_id_col);
		}

	// End table.
	WriteToDoc("\n");
	WriteRepeatedChar('=', max_id_col);
	WriteToDoc(" ");

	if ( max_com_col == 0 )
		WriteToDoc("=");
	else
		WriteRepeatedChar('=', max_com_col);

	WriteToDoc("\n\n");
	}

void BroDoc::WriteBroDocObjList(const BroDocObjList& l, bool wantPublic,
			const char* heading, char underline, bool isShort) const
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

	WriteSectionHeading(heading, underline);

	BroDocObjList filtered_list;

	while ( it != l.end() )
		{
		filtered_list.push_back(*it);
		it = find_if(++it, l.end(), f_ptr);
		}

	if ( isShort )
		WriteBroDocObjTable(filtered_list);
	else
		WriteBroDocObjList(filtered_list);
	}

void BroDoc::WriteBroDocObjList(const BroDocObjMap& m, bool wantPublic,
			const char* heading, char underline, bool isShort) const
	{
	BroDocObjMap::const_iterator it;
	BroDocObjList l;

	for ( it = m.begin(); it != m.end(); ++it )
		l.push_back(it->second);

	WriteBroDocObjList(l, wantPublic, heading, underline, isShort);
	}

void BroDoc::WriteBroDocObjList(const BroDocObjList& l, const char* heading,
			char underline) const
	{
	WriteSectionHeading(heading, underline);
	WriteBroDocObjList(l);
	}

void BroDoc::WriteBroDocObjList(const BroDocObjList& l) const
	{
	for ( BroDocObjList::const_iterator it = l.begin(); it != l.end(); ++it )
		(*it)->WriteReST(reST_file);
	}

void BroDoc::WriteBroDocObjList(const BroDocObjMap& m, const char* heading,
			char underline) const
	{
	BroDocObjMap::const_iterator it;
	BroDocObjList l;

	for ( it = m.begin(); it != m.end(); ++it )
		l.push_back(it->second);

	WriteBroDocObjList(l, heading, underline);
	}

void BroDoc::WriteToDoc(const char* format, ...) const
	{
	va_list argp;
	va_start(argp, format);
	vfprintf(reST_file, format, argp);
	va_end(argp);
	}

void BroDoc::WriteSectionHeading(const char* heading, char underline) const
	{
	WriteToDoc("%s\n", heading);
	WriteRepeatedChar(underline, strlen(heading));
	WriteToDoc("\n");
	}

void BroDoc::WriteRepeatedChar(char c, size_t n) const
	{
	for ( size_t i = 0; i < n; ++i )
		WriteToDoc("%c", c);
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
