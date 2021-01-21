// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include "zeek-config.h"

#include <time.h> // for time_t
#include <set>
#include <list>
#include <string>
#include <vector>
#include <map>

#include "zeek/zeekygen/Info.h"

ZEEK_FORWARD_DECLARE_NAMESPACED(IdentifierInfo, zeek, zeekygen, detail);

namespace zeek::zeekygen::detail {

struct IdInfoComp {
	bool operator() (const IdentifierInfo* lhs,
	                 const IdentifierInfo* rhs) const;
};

using id_info_set = std::set<IdentifierInfo*, IdInfoComp>;
using id_info_list = std::list<IdentifierInfo*>;

/**
 * Information about a Bro script.
 */
class ScriptInfo : public Info {

public:

	/**
	 * Ctor.
	 * @param name Name of script: a path relative to a component in ZEEKPATH.
	 * @param path Absolute path to the script.
	 */
	ScriptInfo(const std::string& name, const std::string& path);

	/**
	 * Associate a Zeekygen summary comment ("##!") with the script.
	 * @param comment String extracted from the comment.
	 */
	void AddComment(const std::string& comment)
		{ comments.push_back(comment); }

	/**
	 * Register a dependency on another script.
	 * @param name Name of a script with this one @loads.  This is the
	 * "normalized" name (a path relative to a component in ZEEKPATH).
	 */
	void AddDependency(const std::string& name)
		{ dependencies.insert(name); }

	/**
	 * Register a module usage (signifying the script may export identifiers
	 * into that modules namespace).
	 * @param name The name of the module.
	 */
	void AddModule(const std::string& name)
		{ module_usages.insert(name); }

	/**
	 * Register an identifier declared by this script.
	 * @param info The identifier info object associated with a script-level
	 * identifier declared by the script.
	 */
	void AddIdentifierInfo(IdentifierInfo* info);

	/**
	 * Register a redef of an identifier done by this script.
	 * @param info The identifier info object associated with the script-level
	 * identifier redef'd by the script.
	 */
	void AddRedef(IdentifierInfo* info)
		{ redefs.insert(info); }

	/**
	 * @return Whether the script is a package loader (i.e. "__load__.zeek").
	 */
	bool IsPkgLoader() const
		{ return is_pkg_loader; }

	/**
	 * @return All the scripts Zeekygen summary comments.
	 */
	std::vector<std::string> GetComments() const;

private:

	typedef std::map<std::string, IdentifierInfo*> id_info_map;
	typedef std::set<std::string> string_set;

	time_t DoGetModificationTime() const override;

	std::string DoName() const override
		{ return name; }

	std::string DoReStructuredText(bool roles_only) const override;

	void DoInitPostScript() override /* override */;

	std::string name;
	std::string path;
	bool is_pkg_loader;
	string_set dependencies;
	string_set module_usages;
	std::vector<std::string> comments;
	id_info_map id_info;
	id_info_list redef_options;
	id_info_list options;
	id_info_list constants;
	id_info_list state_vars;
	id_info_list types;
	id_info_list events;
	id_info_list hooks;
	id_info_list functions;
	id_info_set redefs;
};

} // namespace zeek::zeekygen::detail
