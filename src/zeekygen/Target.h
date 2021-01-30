// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include "zeek-config.h"

#include <map>
#include <string>
#include <vector>
#include <cstdio>

ZEEK_FORWARD_DECLARE_NAMESPACED(Info, zeek, zeekygen, detail);
ZEEK_FORWARD_DECLARE_NAMESPACED(PackageInfo, zeek, zeekygen, detail);
ZEEK_FORWARD_DECLARE_NAMESPACED(ScriptInfo, zeek, zeekygen, detail);
ZEEK_FORWARD_DECLARE_NAMESPACED(IdentifierInfo, zeek, zeekygen, detail);

namespace zeek::zeekygen::detail {

/**
 * Helper class to create files in arbitrary file paths and automatically
 * close it on destruction.
 */
struct TargetFile {
	/**
	 * Open a file.
	 * @param arg_name Path to a file to create.  It's a fatal error if
	 * creating it fails.  Creating it will also create any intermediate
	 * directories that don't already exist.
	 *
	 */
	explicit TargetFile(const std::string& arg_name);

	/**
	 * Close the file.
	 */
	~TargetFile();

	std::string name; /**< File name. */
	FILE* f; /**< File stream. */
};

/**
 * A Zeekygen target abstract base class.  A target is generally any portion of
 * documentation that Bro can build.  It's identified by a type (e.g. script,
 * identifier, package), a pattern (e.g. "example.zeek", "HTTP::Info"), and
 * a path to an output file.
 */
class Target {

public:

	/**
	 * Ctor.
	 * @param arg_name output file name of the target.
	 * @param arg_pattern pattern of info objects the target depends upon.  Only
	 * exact string and simple prefix matching is currently allowed.
	 */
	Target(const std::string& arg_name, const std::string& arg_pattern);

	/**
	 * Dtor.
	 */
	virtual ~Target()
		{ }

	/**
	 * Filter out any dependency information from a set of all known info.
	 * @param infos All known info objects.
	 */
	void FindDependencies(const std::vector<Info*>& infos)
		{ DoFindDependencies(infos); }

	/**
	 * Build the target by generating its output file.  Implementations may
	 * not always write to the output file if they determine an existing
	 * version is already up-to-date.
	 */
	void Generate() const
		{ DoGenerate(); }

	/**
	 * Check if a particular info object matches the target pattern.
	 * Currently only exact string and simple prefix matching patterns are
	 * used.  E.g. for prefix matching "HTTP::*" or "base/protocols/http*".
	 * @param info An info object for some thing that is documentable.
	 * @return true if it matches, else false.
	 */
	bool MatchesPattern(Info* info) const;

	/**
	 * @return The output file name of the target.
	 */
	std::string Name() const
		{ return name; }

	/**
	 * @return The pattern string of the target.
	 */
	std::string Pattern() const
		{ return pattern; }

private:

	virtual void DoFindDependencies(const std::vector<Info*>& infos) = 0;

	virtual void DoGenerate() const = 0;

	std::string name;
	std::string pattern;
	std::string prefix;
};

template<class T>
static Target* create_target(const std::string& name,
                             const std::string& pattern)
	{
	return new T(name, pattern);
	}

/**
 * Factory for creating Target instances.
 */
class TargetFactory {

public:

	/**
	 * Register a new target type.
	 * @param type_name The target type name as it will appear in Zeekygen
	 * config files.
	 */
	template<class T>
	void Register(const std::string& type_name)
		{
		target_creators[type_name] = &create_target<T>;
		}

	/**
	 * Instantiate a target.
	 * @param type_name The target type name as it appears in Zeekygen config
	 * files.
	 * @param name The output file name of the target.
	 * @param pattern The dependency pattern of the target.
	 * @return A new target instance or a pointer if \a type_name is not
	 * registered.
	 */
	Target* Create(const std::string& type_name,
	               const std::string& name, const std::string& pattern)
		{
		target_creator_map::const_iterator it = target_creators.find(type_name);

		if ( it == target_creators.end() )
			return nullptr;

		return it->second(name, pattern);
		}

private:

	typedef Target* (*TargetFactoryFn)(const std::string& name,
	                                  const std::string& pattern);
	typedef std::map<std::string, TargetFactoryFn> target_creator_map;
	target_creator_map target_creators;
};

/**
 * Target to build analyzer documentation.
 */
class AnalyzerTarget : public Target {
public:

	/**
	 * Writes out plugin index documentation for all analyzer plugins.
	 * @param f an open file stream to write docs into.
	 */
	void CreateAnalyzerDoc(FILE* f) const
		{ return DoCreateAnalyzerDoc(f); }

protected:

	typedef void (*doc_creator_fn)(FILE*);

	AnalyzerTarget(const std::string& name, const std::string& pattern)
		: Target(name, pattern)
		{ }

private:

	void DoFindDependencies(const std::vector<Info*>& infos) override;

	void DoGenerate() const override;

	virtual void DoCreateAnalyzerDoc(FILE* f) const = 0;
};

/**
 * Target to build protocol analyzer documentation.
 */
class ProtoAnalyzerTarget : public AnalyzerTarget {
public:

	/**
	 * Ctor.
	 * @param name Output file name.
	 * @param pattern Dependency pattern.
	 */
	ProtoAnalyzerTarget(const std::string& name, const std::string& pattern)
		: AnalyzerTarget(name, pattern)
		{ }

private:

	void DoCreateAnalyzerDoc(FILE* f) const override;
};

/**
 * Target to build file analyzer documentation.
 */
class FileAnalyzerTarget : public AnalyzerTarget {
public:

	/**
	 * Ctor.
	 * @param name Output file name.
	 * @param pattern Dependency pattern.
	 */
	FileAnalyzerTarget(const std::string& name, const std::string& pattern)
		: AnalyzerTarget(name, pattern)
		{ }

private:

	void DoCreateAnalyzerDoc(FILE* f) const override;
};

/**
 * Target to build packet analyzer documentation.
 */
class PacketAnalyzerTarget : public AnalyzerTarget {
public:

	/**
	 * Ctor.
	 * @param name Output file name.
	 * @param pattern Dependency pattern.
	 */
	PacketAnalyzerTarget(const std::string& name, const std::string& pattern)
		: AnalyzerTarget(name, pattern)
		{ }

private:

	void DoCreateAnalyzerDoc(FILE* f) const override;
};

/**
 * Target to build package documentation.
 */
class PackageTarget : public Target {
public:

	/**
	 * Ctor.
	 * @param name Output file name.
	 * @param pattern Dependency pattern.
	 */
	PackageTarget(const std::string& name, const std::string& pattern)
		: Target(name, pattern), pkg_deps(), script_deps(), pkg_manifest()
		{ }

private:

	void DoFindDependencies(const std::vector<Info*>& infos) override;

	void DoGenerate() const override;

	std::vector<PackageInfo*> pkg_deps;
	std::vector<ScriptInfo*> script_deps;
	typedef std::map<PackageInfo*,std::vector<ScriptInfo*> > manifest_t;
	manifest_t pkg_manifest;
};

/**
 * Target to build package index documentation.
 */
class PackageIndexTarget : public Target {
public:

	/**
	 * Ctor.
	 * @param name Output file name.
	 * @param pattern Dependency pattern.
	 */
	PackageIndexTarget(const std::string& name, const std::string& pattern)
		: Target(name, pattern), pkg_deps()
		{ }

private:

	void DoFindDependencies(const std::vector<Info*>& infos) override;

	void DoGenerate() const override;

	std::vector<PackageInfo*> pkg_deps;
};

/**
 * Target to build script documentation.
 */
class ScriptTarget : public Target {
public:

	/**
	 * Ctor.
	 * @param name Output file name or directory.  If it's a directory,
	 * then one document for each script that matches the pattern is written to
	 * the directory in a directory structure which mirrors the script's path
	 * relative to a component in ZEEKPATH.
	 * @param pattern Dependency pattern.
	 */
	ScriptTarget(const std::string& name, const std::string& pattern)
		: Target(name, pattern), script_deps()
		{ }

	~ScriptTarget() override
		{ for ( size_t i = 0; i < pkg_deps.size(); ++i ) delete pkg_deps[i]; }

protected:

	std::vector<ScriptInfo*> script_deps;

private:

	void DoFindDependencies(const std::vector<Info*>& infos) override;

	void DoGenerate() const override;

	bool IsDir() const
		{ return Name()[Name().size() - 1] == '/'; }

	std::vector<Target*> pkg_deps;
};

/**
 * Target to build script summary documentation.
 */
class ScriptSummaryTarget : public ScriptTarget {
public:

	/**
	 * Ctor.
	 * @param name Output file name.
	 * @param pattern Dependency pattern.
	 */
	ScriptSummaryTarget(const std::string& name, const std::string& pattern)
		: ScriptTarget(name, pattern)
		{ }

private:

	void DoGenerate() const override /* override */;
};

/**
 * Target to build script index documentation.
 */
class ScriptIndexTarget : public ScriptTarget {
public:

	/**
	 * Ctor.
	 * @param name Output file name.
	 * @param pattern Dependency pattern.
	 */
	ScriptIndexTarget(const std::string& name, const std::string& pattern)
		: ScriptTarget(name, pattern)
		{ }

private:

	void DoGenerate() const override /* override */;
};

/**
 * Target to build identifier documentation.
 */
class IdentifierTarget : public Target {
public:

	/**
	 * Ctor.
	 * @param name Output file name.
	 * @param pattern Dependency pattern.
	 */
	IdentifierTarget(const std::string& name, const std::string& pattern)
		: Target(name, pattern), id_deps()
		{ }

private:

	void DoFindDependencies(const std::vector<Info*>& infos) override;

	void DoGenerate() const override;

	std::vector<IdentifierInfo*> id_deps;
};

} // namespace zeek::zeekygen::detail
