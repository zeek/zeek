// See the file "COPYING" in the main distribution directory for copyright.

#ifndef BROXYGEN_MANAGER_H
#define BROXYGEN_MANAGER_H

#include "Configuration.h"
#include "Info.h"
#include "PackageInfo.h"
#include "ScriptInfo.h"
#include "IdentifierInfo.h"

#include "Reporter.h"
#include "ID.h"
#include "Type.h"
#include "Val.h"

#include <string>
#include <vector>
#include <map>
#include <ctime>
#include <sys/stat.h>
#include <errno.h>

namespace broxygen {

/**
 * Map of info objects.  Just a wrapper around std::map to improve code
 * readability (less typedefs for specific map types and not having to use
 * iterators directly to find a particular info object).
 */
template<class T>
struct InfoMap {
	typedef std::map<std::string, T*> map_type;

	/**
	 * @param name Name of an info object to retrieve.
	 * @return The info object associated with \a name.
	 */
	T* GetInfo(const std::string& name) const
		{
		typename map_type::const_iterator it = map.find(name);
		return it == map.end() ? 0 : it->second;
		}

	map_type map;
};

/**
 * Manages all documentation tracking and generation.
 */
class Manager {

public:

	/**
	 * Ctor.
	 * @param config Path to a Broxygen config file if documentation is to be
	 * written to disk.
	 * @param bro_command The command used to invoke the bro process.
	 * It's used when checking for out-of-date targets.  If the bro binary is
	 * newer then a target, it needs to be rebuilt.
	 */
	Manager(const std::string& config, const std::string& bro_command);

	/**
	 * Dtor.
	 */
	~Manager();

	/**
	 * Do initialization that needs to happen before scripts are parsed.
	 * Currently nothing outside of what's done in ctor is needed.
	 */
	void InitPreScript();

	/**
	 * Do initialization that needs to happen after scripts are parsed.
	 * This is primarly dependency resolution/filtering.
	 */
	void InitPostScript();

	/**
	 * Builds all Broxygen targets specified by config file and write out
	 * documentation to disk.
	 */
	void GenerateDocs() const;

	/**
	 * Register Bro script for which information/documentation will be gathered.
	 * @param path Absolute path to Bro script.
	 */
	void Script(const std::string& path);

	/**
	 * Register Bro script dependency ("@load").
	 * @param path Absolute path to a Bro script.
	 * @param dep Absolute path to a Bro script being "@load"d from script given
	 * by \a path.
	 */
	void ScriptDependency(const std::string& path, const std::string& dep);

	/**
	 * Register a module usage (script may export identifiers in to the
	 * module namespace).
	 * @param path Absolute path to a Bro script.
	 * @param module The module which script given by \a path is using.
	 */
	void ModuleUsage(const std::string& path, const std::string& module);

	/**
	 * Signal that a record or enum type is now being parsed.
	 * @param id The record or enum type identifier.
	 */
	void StartType(ID* id);

	/**
	 * Register a script-level identifier for which information/documentation
	 * will be gathered.
	 * @param id The script-level identifier.
	 */
	void Identifier(ID* id);

	/**
	 * Register a record-field for which information/documentation will be
	 * gathered.
	 * @param id The identifier of the record type which has the field.
	 * @param field The field name/type information.
	 * @param path Absolute path to a Bro script in which this field is
	 * declared.  This can be different from the place where the record type
	 * is declared due to redefs.
	 */
	void RecordField(const ID* id, const TypeDecl* field,
	                 const std::string& path);

	/**
	 * Register a redefinition of a particular identifier.
	 * @param id The identifier being redef'd.
	 * @param path Absolute path to a Bro script doing the redef.
	 */
	void Redef(const ID* id, const std::string& path);

	/**
	 * Register Broxygen script summary content.
	 * @param path Absolute path to a Bro script.
	 * @param comment Broxygen-style summary comment ("##!") to associate with
	 * script given by \a path.
	 */
	void SummaryComment(const std::string& path, const std::string& comment);

	/**
	 * Register a Broxygen comment ("##") for an upcoming identifier (i.e.
	 * this content is buffered and consumed by next identifier/field
	 * declaration.
	 * @param comment Content of the Broxygen comment.
	 */
	void PreComment(const std::string& comment);

	/**
	 * Register a Broxygen comment ("##<") for the last identifier seen.
	 * @param comment Content of the Broxygen comment.
	 * @param identifier_hint Expected name of identifier with which to
	 * associate \a comment.
	 */
	void PostComment(const std::string& comment,
	                 const std::string& identifier_hint = "");

	/**
	 * @param id Name of script-level enum identifier.
	 * @return The name of the enum's type.
	 */
	std::string GetEnumTypeName(const std::string& id) const;

	/**
	 * @param name Name of a script-level identifier.
	 * @return an identifier info object associated with \a name or a null
	 * pointer if it's not a known identifier.
	 */
	IdentifierInfo* GetIdentifierInfo(const std::string& name) const
	    { return identifiers.GetInfo(name); }

	/**
	 * @param name Name of a Bro script ("normalized" to be a path relative
	 * to a component within BROPATH).
	 * @return a script info object associated with \a name or a null pointer
	 * if it's not a known script name.
	 */
	ScriptInfo* GetScriptInfo(const std::string& name) const
	    { return scripts.GetInfo(name); }

	/**
	 * @param name Nmae of a Bro script package ("normalized" to be a path
	 * relative to a component within BROPATH).
	 * @return a package info object assocated with \a name or a null pointer
	 * if it's not a known package name.
	 */
	PackageInfo* GetPackageInfo(const std::string& name) const
	    { return packages.GetInfo(name); }

	/**
	 * Check if a Broxygen target is up-to-date.
	 * @param target_file output file of a Broxygen target.
	 * @param dependencies all dependencies of the target.
	 * @return true if modification time of \a target_file is newer than
	 * modification time of Bro binary, Broxygen config file, and all
	 * dependencies, else false.
	 */
	template <class T>
	bool IsUpToDate(const std::string& target_file,
	                const std::vector<T*>& dependencies) const;

private:

	typedef std::vector<std::string> comment_buffer_t;
	typedef std::map<std::string, comment_buffer_t> comment_buffer_map_t;

	IdentifierInfo* CreateIdentifierInfo(ID* id, ScriptInfo* script);

	bool disabled;
	comment_buffer_t comment_buffer; // For whatever next identifier comes in.
	comment_buffer_map_t comment_buffer_map; // For a particular identifier.
	InfoMap<PackageInfo> packages;
	InfoMap<ScriptInfo> scripts;
	InfoMap<IdentifierInfo> identifiers;
	std::vector<Info*> all_info;
	IdentifierInfo* last_identifier_seen;
	IdentifierInfo* incomplete_type;
	std::map<std::string, std::string> enum_mappings; // enum id -> enum type id
	Config config;
	time_t bro_mtime;
};

template <class T>
bool Manager::IsUpToDate(const string& target_file,
                         const vector<T*>& dependencies) const
	{
	struct stat s;

	if ( stat(target_file.c_str(), &s) < 0 )
		{
		if ( errno == ENOENT )
			// Doesn't exist.
			return false;

		reporter->InternalError("Broxygen failed to stat target file '%s': %s",
		                        target_file.c_str(), strerror(errno));
		}

	if ( difftime(bro_mtime, s.st_mtime) > 0 )
		return false;

	if ( difftime(config.GetModificationTime(), s.st_mtime) > 0 )
		return false;

	for ( size_t i = 0; i < dependencies.size(); ++i )
		if ( difftime(dependencies[i]->GetModificationTime(), s.st_mtime) > 0 )
			return false;

	return true;
	}

} // namespace broxygen

extern broxygen::Manager* broxygen_mgr;

#endif
