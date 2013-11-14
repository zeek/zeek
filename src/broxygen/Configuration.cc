#include "Configuration.h"
#include "Manager.h"

#include "util.h"
#include "Reporter.h"

#include <fstream>
#include <vector>
#include <algorithm>
#include <map>
#include <cstdio>
#include <sys/stat.h>

using namespace broxygen;
using namespace std;

typedef map<string, Target::factory_fn> target_factory_map;

static target_factory_map create_target_factory_map()
	{
	target_factory_map rval;
	rval["package_index"] =  &PackageIndexTarget::Instantiate;
	rval["package"] =        &PackageTarget::Instantiate;
	rval["proto_analyzer"] = &ProtoAnalyzerTarget::Instantiate;
	rval["file_analyzer"] =  &FileAnalyzerTarget::Instantiate;
	rval["script_summary"] = &ScriptSummaryTarget::Instantiate;
	rval["script_index"] =   &ScriptIndexTarget::Instantiate;
	rval["script"] =         &ScriptTarget::Instantiate;
	rval["identifier"] =     &IdentifierTarget::Instantiate;
	return rval;
	}

static target_factory_map target_instantiators = create_target_factory_map();

struct TargetFile {
	TargetFile(const string& arg_name)
		: name(arg_name), f()
		{
		if ( name.find('/') != string::npos )
			{
			string dir = SafeDirname(name).result;

			if ( ! ensure_intermediate_dirs(dir.c_str()) )
				reporter->FatalError("Broxygen failed to make dir %s",
				                     dir.c_str());
			}

		f = fopen(name.c_str(), "w");

		if ( ! f )
			reporter->FatalError("Broxygen failed to open '%s' for writing: %s",
			                     name.c_str(), strerror(errno));
		}

	~TargetFile()
		{
		if ( f )
			fclose(f);

		DBG_LOG(DBG_BROXYGEN, "Wrote out-of-date target '%s'", name.c_str());
		}

	string name;
	FILE* f;
};

template<class T>
static vector<T*> filter_matching_docs(const vector<Document*>& from, Target* t)
	{
	vector<T*> rval;

	for ( size_t i = 0; i < from.size(); ++i )
		{
		T* d = dynamic_cast<T*>(from[i]);

		if ( ! d )
			continue;

		if ( t->MatchesPattern(d) )
			{
			DBG_LOG(DBG_BROXYGEN, "Doc '%s' matched pattern for target '%s'",
			        d->Name().c_str(), t->Name().c_str());
			rval.push_back(d);
			}
		}

	return rval;
	}

Target::Target(const string& arg_name, const string& arg_pattern)
    : name(arg_name), pattern(arg_pattern), prefix()
	{
	size_t pos = pattern.find('*');

	if ( pos == 0 || pos == string::npos )
		return;

	prefix = pattern.substr(0, pos);
	}

bool Target::MatchesPattern(Document* doc) const
	{
	if ( pattern == "*" )
		return true;

	if ( prefix.empty() )
		return doc->Name() == pattern;

	return ! strncmp(doc->Name().c_str(), prefix.c_str(), prefix.size());
	}

void AnalyzerTarget::DoFindDependencies(const std::vector<Document *>& docs)
	{
	// TODO: really should add to dependency list the tag type's ID and
	// all bif items for matching analyzer plugins, but that's all dependent
	// on the bro binary itself, so I'm cheating.
	}

void AnalyzerTarget::DoGenerate() const
	{
	if ( broxygen_mgr->IsUpToDate(Name(), vector<Document*>()) )
		return;

	if ( Pattern() != "*" )
		reporter->InternalWarning("Broxygen only implements analyzer target"
		                          " pattern '*'");

	TargetFile file(Name());
	doc_creator_callback(file.f);
	}

void PackageTarget::DoFindDependencies(const vector<Document*>& docs)
	{
	pkg_deps = filter_matching_docs<PackageDocument>(docs, this);

	if ( pkg_deps.empty() )
		reporter->FatalError("No match for Broxygen target '%s' pattern '%s'",
		                     Name().c_str(), Pattern().c_str());

	for ( size_t i = 0; i < docs.size(); ++i )
		{
		ScriptDocument* script = dynamic_cast<ScriptDocument*>(docs[i]);

		if ( ! script )
			continue;

		for ( size_t j = 0; j < pkg_deps.size(); ++j )
			{
			if ( strncmp(script->Name().c_str(), pkg_deps[j]->Name().c_str(),
			             pkg_deps[j]->Name().size()))
				continue;

			DBG_LOG(DBG_BROXYGEN, "Script %s associated with package %s",
			        script->Name().c_str(), pkg_deps[j]->Name().c_str());
			pkg_manifest[pkg_deps[j]].push_back(script);
			script_deps.push_back(script);
			}
		}
	}

void PackageTarget::DoGenerate() const
	{
	if ( broxygen_mgr->IsUpToDate(Name(), script_deps) )
		return;

	TargetFile file(Name());

	for ( manifest_t::const_iterator it = pkg_manifest.begin();
	      it != pkg_manifest.end(); ++it )
		{
		fprintf(file.f, "Package: %s\n\n", it->first->Name().c_str());

		for ( size_t i = 0; i < it->second.size(); ++i )
			{
			fprintf(file.f, "   :doc:`%s`\n", it->second[i]->Name().c_str());

			vector<string> cmnts = it->second[i]->GetComments();

			for ( size_t j = 0; j < cmnts.size(); ++j )
				fprintf(file.f, "      %s\n", cmnts[j].c_str());

			fprintf(file.f, "\n");
			}
		}
	}

void PackageIndexTarget::DoFindDependencies(const vector<Document*>& docs)
	{
	pkg_deps = filter_matching_docs<PackageDocument>(docs, this);

	if ( pkg_deps.empty() )
		reporter->FatalError("No match for Broxygen target '%s' pattern '%s'",
		                     Name().c_str(), Pattern().c_str());
	}

void PackageIndexTarget::DoGenerate() const
	{
	if ( broxygen_mgr->IsUpToDate(Name(), pkg_deps) )
		return;

	TargetFile file(Name());

	for ( size_t i = 0; i < pkg_deps.size(); ++i )
		fprintf(file.f, "%s\n", pkg_deps[i]->ReStructuredText().c_str());
	}

void ScriptTarget::DoFindDependencies(const vector<Document*>& docs)
    {
	script_deps = filter_matching_docs<ScriptDocument>(docs, this);

	if ( script_deps.empty() )
		reporter->FatalError("No match for Broxygen target '%s' pattern '%s'",
		                     Name().c_str(), Pattern().c_str());
	}

void ScriptTarget::DoGenerate() const
    {
	if ( Name()[Name().size() - 1] == '/' )
		{
		// Target name is a dir, matching scripts are written within that dir
		// with a dir tree that parallels the script's BROPATH location.

		for ( size_t i = 0; i < script_deps.size(); ++i )
			{
			string target_filename = Name() + script_deps[i]->Name();
			size_t pos = target_filename.rfind(".bro");

			if ( pos == target_filename.size() - 4 )
				target_filename.replace(pos, 4, ".rst");
			else
				target_filename += ".rst";

			vector<ScriptDocument*> dep;
			dep.push_back(script_deps[i]);

			if ( broxygen_mgr->IsUpToDate(target_filename, dep) )
				continue;

			TargetFile file(target_filename);

			fprintf(file.f, "%s\n", script_deps[i]->ReStructuredText().c_str());
			}

		// TODO: could possibly take inventory of files in the dir beforehand,
		// track all files written, then compare afterwards in order to remove
		// stale files.
		return;
		}

	// Target is a single file, all matching scripts get written there.

	if ( broxygen_mgr->IsUpToDate(Name(), script_deps) )
		return;

	TargetFile file(Name());

	for ( size_t i = 0; i < script_deps.size(); ++i )
		fprintf(file.f, "%s\n", script_deps[i]->ReStructuredText().c_str());
	}

void ScriptSummaryTarget::DoGenerate() const
	{
	if ( broxygen_mgr->IsUpToDate(Name(), script_deps) )
		return;

	TargetFile file(Name());

	for ( size_t i = 0; i < script_deps.size(); ++i )
		{
		ScriptDocument* d = dynamic_cast<ScriptDocument*>(script_deps[i]);

		if ( ! d )
			continue;

		fprintf(file.f, ":doc:`/scripts/%s`\n", d->Name().c_str());

		vector<string> cmnts = d->GetComments();

		for ( size_t i = 0; i < cmnts.size(); ++i )
			fprintf(file.f, "    %s\n", cmnts[i].c_str());

		fprintf(file.f, "\n");
		}
	}

void ScriptIndexTarget::DoGenerate() const
	{
	if ( broxygen_mgr->IsUpToDate(Name(), script_deps) )
		return;

	TargetFile file(Name());

	fprintf(file.f, ".. toctree::\n");
	fprintf(file.f, "   :maxdepth: 1\n\n");

	for ( size_t i = 0; i < script_deps.size(); ++i )
		{
		ScriptDocument* d = dynamic_cast<ScriptDocument*>(script_deps[i]);

		if ( ! d )
			continue;

		fprintf(file.f, "   %s <%s>\n", d->Name().c_str(), d->Name().c_str());
		}
	}

void IdentifierTarget::DoFindDependencies(const vector<Document*>& docs)
	{
	id_deps = filter_matching_docs<IdentifierDocument>(docs, this);

	if ( id_deps.empty() )
		reporter->FatalError("No match for Broxygen target '%s' pattern '%s'",
		                     Name().c_str(), Pattern().c_str());
	}

void IdentifierTarget::DoGenerate() const
	{
	if ( broxygen_mgr->IsUpToDate(Name(), id_deps) )
		return;

	TargetFile file(Name());

	for ( size_t i = 0; i < id_deps.size(); ++i )
		fprintf(file.f, "%s\n\n", id_deps[i]->ReStructuredText().c_str());
	}

Config::Config(const string& arg_file, const string& delim)
	: file(arg_file), targets()
	{
	if ( file.empty() )
		return;

	ifstream f(file.c_str());

	if ( ! f.is_open() )
		reporter->FatalError("failed to open Broxygen config file '%s': %s",
		                     file.c_str(), strerror(errno));

	string line;
	unsigned int line_number = 0;

	while ( getline(f, line) )
		{
		++line_number;
		vector<string> tokens;
		tokenize_string(line, delim, &tokens);
		tokens.erase(remove(tokens.begin(), tokens.end(), ""), tokens.end());

		if ( tokens.empty() )
			// Blank line.
			continue;

		if ( ! tokens[0].empty() && tokens[0][0] == '#' )
			// Comment
			continue;

		if ( tokens.size() != 3 )
			reporter->FatalError("malformed Broxygen target in %s:%u: %s",
			                     file.c_str(), line_number, line.c_str());

		target_factory_map::const_iterator it =
		        target_instantiators.find(tokens[0]);

		if ( it == target_instantiators.end() )
			reporter->FatalError("unkown Broxygen target type: %s",
			                     tokens[0].c_str());

		targets.push_back(it->second(tokens[1], tokens[2]));
		}

	if ( f.bad() )
		reporter->InternalError("error reading Broxygen config file '%s': %s",
		                        file.c_str(), strerror(errno));
	}

Config::~Config()
	{
	for ( size_t i = 0; i < targets.size(); ++i )
		delete targets[i];
	}

void Config::FindDependencies(const vector<Document*>& docs)
	{
	for ( size_t i = 0; i < targets.size(); ++i )
		targets[i]->FindDependencies(docs);
	}

void Config::GenerateDocs() const
	{
	for ( size_t i = 0; i < targets.size(); ++i )
		targets[i]->Generate();
	}

time_t Config::GetModificationTime() const
	{
	struct stat s;

	if ( stat(file.c_str(), &s) < 0 )
		reporter->InternalError("Broxygen can't stat config file %s: %s",
		                        file.c_str(), strerror(errno));

	return s.st_mtime;
	}
