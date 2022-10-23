// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include <sys/stat.h>
#include <cerrno>
#include <ctime>
#include <map>
#include <string>
#include <vector>

#include "zeek/ID.h"
#include "zeek/Reporter.h"
#include "zeek/util.h"
#include "zeek/zeekygen/Configuration.h"

namespace zeek
	{

class TypeDecl;

namespace zeekygen::detail
	{

class PackageInfo;
class ScriptInfo;

/**
 * Map of info objects.  Just a wrapper around std::map to improve code
 * readability (less typedefs for specific map types and not having to use
 * iterators directly to find a particular info object).
 */
template <class T> struct InfoMap
	{
	using map_type = std::map<std::string, T*>;

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
class Manager
	{

public:
	/**
	 * Ctor.
	 * @param config Path to a Zeekygen config file if documentation is to be
	 * written to disk.
	 * @param command The command used to invoke the Zeek process.
	 * It's used when checking for out-of-date targets.  If the Zeek binary is
	 * newer then a target, it needs to be rebuilt.
	 */
	Manager(const std::string& config, const std::string& command);

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
	 * Builds all Zeekygen targets specified by config file and write out
	 * documentation to disk.
	 */
	void GenerateDocs() const;

	/**
	 * Register Zeek script for which information/documentation will be gathered.
	 * @param path Absolute path to Zeek script.
	 */
	void Script(const std::string& path);

	/**
	 * Register Zeek script dependency ("@load").
	 * @param path Absolute path to a Zeek script.
	 * @param dep Absolute path to a Zeek script being "@load"d from script given
	 * by \a path.
	 */
	void ScriptDependency(const std::string& path, const std::string& dep);

	/**
	 * Register a module usage (script may export identifiers in to the
	 * module namespace).
	 * @param path Absolute path to a Zeek script.
	 * @param module The module which script given by \a path is using.
	 */
	void ModuleUsage(const std::string& path, const std::string& module);

	/**
	 * Signal that a record or enum type is now being parsed.
	 * @param id The record or enum type identifier.
	 */
	void StartType(zeek::detail::IDPtr id);

	/**
	 * Register a script-level identifier for which information/documentation
	 * will be gathered.
	 * @param id The script-level identifier.
	 * @param from_redef  The identifier was created from a redef (e.g. an enum).
	 */
	void Identifier(zeek::detail::IDPtr id, bool from_redef = false);

	/**
	 * Register a record-field for which information/documentation will be
	 * gathered.
	 * @param id The identifier of the record type which has the field.
	 * @param field The field name/type information.
	 * @param path Absolute path to a Zeek script in which this field is
	 * declared.  This can be different from the place where the record type
	 * is declared due to redefs.
	 * @param from_redef  The field is from a record redefinition.
	 */
	void RecordField(const zeek::detail::ID* id, const TypeDecl* field, const std::string& path,
	                 bool from_redef);

	/**
	 * Register a redefinition of a particular identifier.
	 * @param id The identifier being redef'd.
	 * @param path Absolute path to a Zeek script doing the redef.
	 * @param ic The initialization class that was used (e.g. =, +=, -=).
	 * @param init_expr The initialization expression that was used.
	 */
	void Redef(const zeek::detail::ID* id, const std::string& path, zeek::detail::InitClass ic,
	           zeek::detail::ExprPtr init_expr);
	void Redef(const zeek::detail::ID* id, const std::string& path,
	           zeek::detail::InitClass ic = zeek::detail::INIT_NONE);

	/**
	 * Register Zeekygen script summary content.
	 * @param path Absolute path to a Zeek script.
	 * @param comment Zeekygen-style summary comment ("##!") to associate with
	 * script given by \a path.
	 */
	void SummaryComment(const std::string& path, const std::string& comment);

	/**
	 * Register a Zeekygen comment ("##") for an upcoming identifier (i.e.
	 * this content is buffered and consumed by next identifier/field
	 * declaration.
	 * @param comment Content of the Zeekygen comment.
	 */
	void PreComment(const std::string& comment);

	/**
	 * Register a Zeekygen comment ("##<") for the last identifier seen.
	 * @param comment Content of the Zeekygen comment.
	 * @param identifier_hint Expected name of identifier with which to
	 * associate \a comment.
	 */
	void PostComment(const std::string& comment, const std::string& identifier_hint = "");

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
		{
		return identifiers.GetInfo(name);
		}

	/**
	 * @param name Name of a Zeek script ("normalized" to be a path relative
	 * to a component within ZEEKPATH).
	 * @return a script info object associated with \a name or a null pointer
	 * if it's not a known script name.
	 */
	ScriptInfo* GetScriptInfo(const std::string& name) const { return scripts.GetInfo(name); }

	/**
	 * @param name Name of a Zeek script package ("normalized" to be a path
	 * relative to a component within ZEEKPATH).
	 * @return a package info object associated with \a name or a null pointer
	 * if it's not a known package name.
	 */
	PackageInfo* GetPackageInfo(const std::string& name) const { return packages.GetInfo(name); }

	/**
	 * Check if a Zeekygen target is up-to-date.
	 * @param target_file output file of a Zeekygen target.
	 * @param dependencies all dependencies of the target.
	 * @return true if modification time of \a target_file is newer than
	 * modification time of Zeek binary, Zeekygen config file, and all
	 * dependencies, else false.
	 */
	template <class T>
	bool IsUpToDate(const std::string& target_file, const std::vector<T*>& dependencies) const;

private:
	using comment_buffer_t = std::vector<std::string>;
	using comment_buffer_map_t = std::map<std::string, comment_buffer_t>;

	IdentifierInfo* CreateIdentifierInfo(zeek::detail::IDPtr id, ScriptInfo* script,
	                                     bool from_redef = false);

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
	time_t mtime;
	};

template <class T>
bool Manager::IsUpToDate(const std::string& target_file, const std::vector<T*>& dependencies) const
	{
	struct stat s;

	if ( stat(target_file.c_str(), &s) < 0 )
		{
		if ( errno == ENOENT )
			// Doesn't exist.
			return false;

		reporter->InternalError("Zeekygen failed to stat target file '%s': %s", target_file.c_str(),
		                        strerror(errno));
		}

	if ( difftime(mtime, s.st_mtime) > 0 )
		return false;

	if ( difftime(config.GetModificationTime(), s.st_mtime) > 0 )
		return false;

	for ( size_t i = 0; i < dependencies.size(); ++i )
		if ( difftime(dependencies[i]->GetModificationTime(), s.st_mtime) > 0 )
			return false;

	return true;
	}

	} // namespace zeekygen::detail

namespace detail
	{

extern zeekygen::detail::Manager* zeekygen_mgr;

	} // namespace detail
	} // namespace zeek
