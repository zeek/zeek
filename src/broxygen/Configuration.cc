#include "Configuration.h"

#include "util.h"
#include "Reporter.h"

#include <fstream>
#include <vector>
#include <algorithm>
#include <map>

using namespace broxygen;
using namespace std;

typedef map<string, Target::factory_fn> target_factory_map;

static target_factory_map create_target_factory_map()
	{
	target_factory_map rval;
	rval["package_index"] =  &PackageTarget::Instantiate;
	rval["package"] =        &PackageTarget::Instantiate;
	rval["proto_analyzer"] = &ProtoAnalyzerTarget::Instantiate;
	rval["file_analyzer"] =  &FileAnalyzerTarget::Instantiate;
	rval["script_summary"] = &ScriptTarget::Instantiate;
	rval["script_index"] =   &ScriptTarget::Instantiate;
	rval["script"] =         &ScriptTarget::Instantiate;
	rval["identifier"] =     &IdentifierTarget::Instantiate;
	return rval;
	}

static target_factory_map target_instantiators = create_target_factory_map();

bool Target::MatchesPattern(Document* doc) const
	{
	// TODO: prefix matching or full regex?

	if ( doc->Name() == pattern )
		{
		DBG_LOG(DBG_BROXYGEN, "Doc '%s'' matched pattern for target '%s'",
		        doc->Name().c_str(), name.c_str());
		return true;
		}

	return false;
	}

template<class T>
void filter_matching_docs(const std::vector<Document*>& filter_from, Target* t)
	{
	for ( size_t i = 0; i < filter_from.size(); ++i )
		{
		T* d = dynamic_cast<T*>(filter_from[i]);

		if ( ! d )
			continue;

		if ( t->MatchesPattern(d) )
			t->AddDependency(d);
		}
	}

void IdentifierTarget::DoFindDependencies(const std::vector<Document*>& docs)
	{
	filter_matching_docs<IdentifierDocument>(docs, this);
	}

Config::Config(const string& file, const string& delim)
	{
	if ( file.empty() )
		return;

	ifstream f(file.c_str());

	if ( ! f.is_open() )
		reporter->InternalError("failed to open Broxygen config file %s: %s",
		                        file.c_str(), strerror(errno));

	string line;

	while ( getline(f, line) )
		{
		vector<string> tokens;
		tokenize_string(line, delim, &tokens);
		tokens.erase(remove(tokens.begin(), tokens.end(), ""), tokens.end());

		if ( tokens.size() != 3 )
			reporter->InternalError("malformed Broxygen target: %s",
			                        line.c_str());

		target_factory_map::const_iterator it =
		        target_instantiators.find(tokens[0]);

		if ( it == target_instantiators.end() )
			reporter->InternalError("unkown Broxygen target type: %s",
			                        tokens[0].c_str());

		targets.push_back(it->second(tokens[1], tokens[2]));
		}

	if ( f.bad() )
		reporter->InternalError("error reading Broxygen config file %s: %s",
		                        file.c_str(), strerror(errno));
	}

Config::~Config()
	{
	for ( target_list::const_iterator it = targets.begin();
	      it != targets.end(); ++it )
		delete *it;
	}

void Config::FindDependencies(const vector<Document*>& docs)
	{
	for ( target_list::const_iterator it = targets.begin();
	      it != targets.end(); ++it )
		(*it)->FindDependencies(docs);
	}

void Config::GenerateDocs() const
	{
	for ( target_list::const_iterator it = targets.begin();
	      it != targets.end(); ++it )
		(*it)->Generate();
	}
