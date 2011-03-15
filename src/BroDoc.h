#ifndef brodoc_h
#define brodoc_h

#include <cstdio>
#include <cstdarg>
#include <string>
#include <list>

#include "BroDocObj.h"

class BroDoc {
public:
	/**
	 * BroDoc constructor
	 * Given a Bro script, opens new file in the current working directory
	 * that will contain reST documentation generated from the parsing
	 * of the Bro script.  The new reST file will be named similar to
	 * the filename of the Bro script that generates it, except any
	 * ".bro" file extension is stripped and ".rst" takes it place.
	 * If the filename doesn't end in ".bro", then ".rst" is just appended.
	 * @param sourcename The name of the Bro script for which to generate
	 *        documentation.  May contain a path.
	 */
	BroDoc(const std::string& sourcename);

	/**
	 * BroDoc destructor
	 * Closes the file that was opened by the constructor and frees up
	 * memory taken by BroDocObj objects.
	 */
	~BroDoc();

	/**
	 * Write out full reST documentation for the Bro script that was parsed.
	 * BroDoc's default implementation of this function will care
	 * about whether declarations made in the Bro script are part of
	 * the public versus private interface (whether things are declared in
	 * the export section).  Things in a script's export section make it
	 * into the reST output regardless of whether they have ## comments
	 * but things outside the export section are only output into the reST
	 * if they have ## comments.
	 */
	virtual void WriteDocFile() const;

	/**
	 * Schedules some summarizing text to be output directly into the reST doc.
	 * This should be called whenever the scanner sees a line in the Bro script
	 * starting with "##!"
	 * @param s The summary text to add to the reST doc.
	 */
	void AddSummary(const std::string& s) { summary.push_back(s); }

	/**
	 * Schedules an import (@load) to be documented.
	 * This should be called whenever the scanner sees an @load.
	 * @param s The name of the imported script.
	 */
	void AddImport(const std::string& s) { imports.push_back(s); }

	/**
	 * Schedules a namespace (module) to be documented.
	 * This should be called whenever the parser sees a TOK_MODULE.
	 * @param s The namespace (module) identifier's name.
	 */
	void AddModule(const std::string& s) { modules.push_back(s); }

	/**
	 * Sets the way the script changes the "capture_filters" table.
	 * This is determined by the scanner checking for changes to
	 * the "capture_filters" table after each of Bro's input scripts
	 * (given as command line arguments to Bro) are finished being parsed.
	 * @param s The value "capture_filters" as given by TableVal::Describe()
	 */
	void SetPacketFilter(const std::string& s);

	/**
	 * Schedules documentation of a given set of ports being associated
	 * with a particular analyzer as a result of the current script
	 * being loaded -- the way the "dpd_config" table is changed.
	 * @param analyzer An analyzer that changed the "dpd_config" table.
	 * @param ports The set of ports assigned to the analyzer in table.
	 */
	void AddPortAnalysis(const std::string& analyzer, const std::string& ports);

	/**
	 * Sets the author of the script.
	 * The scanner should call this when it sees "## Author: ..."
	 * @param s The name, email, etc. of the script author(s).  Must be
	 *        all on one line.
	 */
	void SetAuthor(const std::string& s) { author_name = s; }

	/**
	 * Schedules documentation of a script option.  An option is
	 * defined as any variable in the script that is declared 'const'
	 * and has the '&redef' attribute.
	 * @param o A pointer to a BroDocObj which contains the internal
	 *        Bro language representation of the script option and
	 *        also any associated comments about it.
	 */
	void AddOption(const BroDocObj* o) { options.push_back(o); }

	/**
	 * Schedules documentation of a script state variable.  A state variable
	 * is defined as any variable in the script that is declared 'global'
	 * @param o A pointer to a BroDocObj which contains the internal
	 *        Bro language representation of the script state variable
	 *        and also any associated comments about it.
	 */
	void AddStateVar(const BroDocObj* o) { state_vars.push_back(o); }

	/**
	 * Schedules documentation of a type declared by the script.
	 * @param o A pointer to a BroDocObj which contains the internal
	 *        Bro language representation of the script option and
	 *        also any associated comments about it.
	 */
	void AddType(const BroDocObj* o) { types.push_back(o); }

	/**
	 * Schedules documentation of a Notice (enum redef) declared by script
	 * @param o A pointer to a BroDocObj which contains the internal
	 *        Bro language representation of the Notice and also
	 *        any associated comments about it.
	 */
	void AddNotice(const BroDocObj* o) { notices = o; }

	/**
	 * Schedules documentation of an event declared by the script.
	 * @param o A pointer to a BroDocObj which contains the internal
	 *        Bro language representation of the script event and
	 *        also any associated comments about it.
	 */
	void AddEvent(const BroDocObj* o) { events.push_back(o); }

   /**
	 * Schedules documentation of a function declared by the script.
	 * @param o A pointer to a BroDocObj which contains the internal
	 *        Bro language representation of the script function and
	 *        also any associated comments about it.
	 */
	void AddFunction(const BroDocObj* o) { functions.push_back(o); }

   /**
	 * Schedules documentation of a redef done by the script
	 * @param o A pointer to a BroDocObj which contains the internal
	 *        Bro language representation of the script identifier
	 *        that was redefined and also any associated comments.
	 */
	void AddRedef(const BroDocObj* o) { redefs.push_back(o); }

	/**
	 * Gets the name of the Bro script source file for which reST
	 * documentation is being generated.
	 * @return A char* to the start of the source file's name.
	 */
	const char* GetSourceFileName() const { return source_filename.c_str(); }

	/**
	 * Gets the name of the generated reST documentation file.
	 * @return A char* to the start of the generated reST file's name.
	 */
	const char* GetOutputFileName() const { return reST_filename.c_str(); }

protected:
	FILE* reST_file;
	std::string reST_filename;
	std::string source_filename;
	std::string author_name;
	std::string packet_filter;

	std::list<std::string> ls;
	std::list<std::string> modules;
	std::list<std::string> summary;
	std::list<std::string> imports;
	std::list<std::string> port_analysis;

	std::list<const BroDocObj*> options;
	std::list<const BroDocObj*> state_vars;
	std::list<const BroDocObj*> types;
	const BroDocObj* notices;
	std::list<const BroDocObj*> events;
	std::list<const BroDocObj*> functions;
	std::list<const BroDocObj*> redefs;

	/**
	 * Writes out a list of strings to the reST document.
	 * If the list is empty, prints a newline character.
	 * @param format A printf style format string for elements of the list
	 *        except for the last one in the list
	 * @param last_format A printf style format string to use for the last
	 *        element of the list
	 * @param l A reference to a list of strings
	 */
	void WriteStringList(const char* format,
	                     const char* last_format,
	                     const std::list<std::string>& l) const;

	/**
	 * @see WriteStringList(const char*, const char*,
	 *                      const std::list<std::string>&>)
	 */
	void WriteStringList(const char* format,
	                     const std::list<std::string>& l) const
		{ WriteStringList(format, format, l); }

	/**
	 * Writes out a list of BroDocObj objects to the reST document
	 * @param l A list of BroDocObj pointers
	 * @param exportCond If true, filter out objects that are not in an
	 *        export section.  If false, filter out those that are in
	 *        an export section.
	 * @param heading The title of the section to create in the reST doc.
	 * @param underline The character to use to underline the reST
	 *        section heading.
	 */
	void WriteBroDocObjList(const std::list<const BroDocObj*>& l,
	                        bool exportCond,
	                        const char* heading,
	                        char underline) const;

	/**
	 * A wrapper to fprintf() that always uses the reST document
	 * for the FILE* argument.
	 * @param format A printf style format string.
	 */
	void WriteToDoc(const char* format, ...) const;

	/**
	 * Writes out a reST section heading
	 * @param heading The title of the heading to create
	 * @param underline The character to use to underline the section title
	 *        within the reST document
	 */
	void WriteSectionHeading(const char* heading, char underline) const;
private:

	/**
	 * Frees memory allocated to BroDocObj's objects in a given list.
	 * @param a reference to a list of BroDocObj pointers
	 */
	void FreeBroDocObjPtrList(std::list<const BroDocObj*>& l);
};

#endif
