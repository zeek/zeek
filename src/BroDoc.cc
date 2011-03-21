#include <cstdio>
#include <cstdarg>
#include <string>
#include <list>

#include "BroDoc.h"
#include "BroDocObj.h"

BroDoc::BroDoc(const std::string& sourcename)
	{
#ifdef DEBUG
	fprintf(stdout, "Documenting source: %s\n", sourcename.c_str());
#endif
	source_filename = sourcename.substr(sourcename.find_last_of('/') + 1);

	size_t ext_pos = source_filename.find_last_of('.');
	std::string ext = source_filename.substr(ext_pos + 1);
	if ( ext_pos == std::string::npos || ext != "bro" )
		{
		if ( source_filename != "bro.init" )
			{
			fprintf(stderr,
			        "Warning: documenting file without .bro extension: %s\n",
			        sourcename.c_str());
			}
		else
			{
			// Force the reST documentation file to be "bro.init.rst"
			ext_pos = std::string::npos;
			}
		}

	reST_filename = source_filename.substr(0, ext_pos);
	reST_filename += ".rst";
	reST_file = fopen(reST_filename.c_str(), "w");

	if ( ! reST_file )
		fprintf(stderr, "Failed to open %s", reST_filename.c_str());
#ifdef DEBUG
	else
		fprintf(stdout, "Created reST document: %s\n", reST_filename.c_str());
#endif
	notices = 0;
	}

BroDoc::~BroDoc()
	{
	if ( reST_file )
		if ( fclose( reST_file ) )
			fprintf(stderr, "Failed to close %s", reST_filename.c_str());
	FreeBroDocObjPtrList(options);
	FreeBroDocObjPtrList(state_vars);
	FreeBroDocObjPtrList(types);
	FreeBroDocObjPtrList(events);
	FreeBroDocObjPtrList(functions);
	FreeBroDocObjPtrList(redefs);
	if ( notices ) delete notices;
	}

void BroDoc::SetPacketFilter(const std::string& s)
	{
	packet_filter = s;
	size_t pos1 = s.find("{\n");
	size_t pos2 = s.find("}");
	if ( pos1 != std::string::npos && pos2 != std::string::npos )
		packet_filter = s.substr(pos1 + 2, pos2 - 2);
	}

void BroDoc::AddPortAnalysis(const std::string& analyzer,
                             const std::string& ports)
	{
	std::string reST_string = analyzer + "::\n" + ports + "\n";
	port_analysis.push_back(reST_string);
	}

void BroDoc::WriteDocFile() const
	{
	WriteToDoc(".. Automatically generated.  Do not edit.\n\n");

	WriteToDoc("%s\n", source_filename.c_str());
	for ( size_t i = 0; i < source_filename.length(); ++i )
		WriteToDoc("=");
	WriteToDoc("\n\n");

	WriteSectionHeading("Summary", '-');
	WriteStringList("%s\n", "%s\n\n", summary);

	WriteToDoc(":Author(s): ");
	WriteStringList("%s, ", "%s\n", authors);

	WriteToDoc(":Namespaces: ");
	WriteStringList("`%s`, ", "`%s`\n", modules);

	WriteToDoc(":Imports: ");
	WriteStringList(":doc:`%s`, ", ":doc:`%s`\n\n", imports);

	WriteSectionHeading("Notices", '-');
	if ( notices )
		notices->WriteReST(reST_file);

	WriteSectionHeading("Port Analysis", '-');
	WriteStringList("%s", port_analysis);

	WriteSectionHeading("Packet Filter", '-');
	WriteToDoc("%s\n", packet_filter.c_str());

	WriteSectionHeading("Public Interface", '-');
	WriteBroDocObjList(options, true, "Options", '~');
	WriteBroDocObjList(state_vars, true, "State Variables", '~');
	WriteBroDocObjList(types, true, "Types", '~');
	WriteBroDocObjList(events, true, "Events", '~');
	WriteBroDocObjList(functions, true, "Functions", '~');
	WriteBroDocObjList(redefs, true, "Redefinitions", '~');

	WriteSectionHeading("Private Interface", '-');
	WriteBroDocObjList(state_vars, false, "State Variables", '~');
	WriteBroDocObjList(types, false, "Types", '~');
	WriteBroDocObjList(events, false, "Events", '~');
	WriteBroDocObjList(functions, false, "Functions", '~');
	WriteBroDocObjList(redefs, false, "Redefinitions", '~');
	}

void BroDoc::WriteStringList(const char* format,
                             const char* last_format,
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

void BroDoc::WriteBroDocObjList(const std::list<const BroDocObj*>& l,
                                bool exportCond,
                                const char* heading,
                                char underline) const
	{
	WriteSectionHeading(heading, underline);
	std::list<const BroDocObj*>::const_iterator it;
	for ( it = l.begin(); it != l.end(); ++it )
		{
		if ( exportCond )
			{
			// write out only those in an export section
			if ( (*it)->IsPublicAPI() )
				(*it)->WriteReST(reST_file);
			}
		else
			{
			// write out only those that have comments and are not exported
			if ( !(*it)->IsPublicAPI() && (*it)->HasDocumentation() )
				(*it)->WriteReST(reST_file);
			}
		}
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
	size_t len = strlen(heading);
	for ( size_t i = 0; i < len; ++i )
		WriteToDoc("%c", underline);
	WriteToDoc("\n");
	}

void BroDoc::FreeBroDocObjPtrList(std::list<const BroDocObj*>& l)
	{
	std::list<const BroDocObj*>::iterator it;
	for ( it = l.begin(); it != l.end(); ++it )
		delete *it;
	l.clear();
	}
