##! This is an example script that demonstrates Zeekygen-style
##! documentation.  It generally will make most sense when viewing
##! the script's raw source code and comparing to the HTML-rendered
##! version.
##!
##! Comments in the from ``##!`` are meant to summarize the script's
##! purpose.  They are transferred directly into the generated
##! `reStructuredText <http://docutils.sourceforge.net/rst.html>`_
##! (reST) document associated with the script.
##!
##! .. tip:: You can embed directives and roles within ``##``-stylized comments.
##!
##! There's also a custom role to reference any identifier node in
##! the Zeek Sphinx domain that's good for "see alsos", e.g.
##!
##! See also: :zeek:see:`ZeekygenExample::a_var`,
##! :zeek:see:`ZeekygenExample::ONE`, :zeek:see:`SSH::Info`
##!
##! And a custom directive does the equivalent references:
##!
##! .. zeek:see:: ZeekygenExample::a_var ZeekygenExample::ONE SSH::Info

# Comments that use a single pound sign (#) are not significant to
# a script's auto-generated documentation, but ones that use a
# double pound sign (##) do matter.  In some cases, like record
# field comments, it's necessary to disambiguate the field with
# which a comment associates: e.g. "##<" can be used on the same line
# as a field to signify the comment relates to it and not the
# following field. "##<" can also be used more generally in any
# variable declarations to associate with the last-declared identifier.
#
# Generally, the auto-doc comments (##) are associated with the
# next declaration/identifier found in the script, but Zeekygen
# will track/render identifiers regardless of whether they have any
# of these special comments associated with them.
#
# The first sentence contained within the "##"-stylized comments for
# a given identifier is special in that it will be used as summary
# text in a table containing all such identifiers and short summaries.
# If there are no sentences (text terminated with '.'), then everything
# in the "##"-stylized comments up until the first empty comment
# is taken as the summary text for a given identifier.

# @load directives are self-documenting, don't use any ``##`` style
# comments with them.
@load base/frameworks/notice
@load base/protocols/http
@load frameworks/software/vulnerable

# "module" statements are self-documenting, don't use any ``##`` style
# comments with them.
module ZeekygenExample;

# Redefinitions of "Notice::Type" are self-documenting, but
# more information can be supplied in two different ways.
redef enum Notice::Type += {
	## Any number of this type of comment
	## will document "Zeekygen_One".
	Zeekygen_One,
	Zeekygen_Two,  ##< Any number of this type of comment
	               ##< will document "ZEEKYGEN_TWO".
	Zeekygen_Three,
	## Omitting comments is fine, and so is mixing ``##`` and ``##<``, but
	Zeekygen_Four,  ##< it's probably best to use only one style consistently.
};

# All redefs are automatically tracked.  Comments of the "##" form can be use
# to further document it, but in some cases, like here, they wouldn't be
# adding any interesting information that's not implicit.
redef enum Log::ID += { LOG };

# Only identifiers declared in an export section will show up in generated docs.

export {

	## Documentation for the "SimpleEnum" type goes here.
	## It can span multiple lines.
	type SimpleEnum: enum {
		## Documentation for particular enum values is added like this.
		## And can also span multiple lines.
		ONE,
		TWO,  ##< Or this style is valid to document the preceding enum value.
		THREE,
	};

	## Document the "SimpleEnum" redef here with any special info regarding
	## the *redef* itself.
	redef enum SimpleEnum  += {
		FOUR, ##< And some documentation for "FOUR".
		## Also "FIVE".
		FIVE
	};

	## General documentation for a type "SimpleRecord" goes here.
	## The way fields can be documented is similar to what's already seen
	## for enums.
	type SimpleRecord: record {
		## Counts something.
		field1: count;
		field2: bool; ##< Toggles something.
	};

	## Document the record extension *redef* itself here.
	redef record SimpleRecord += {
		## Document the extending field like this.
		field_ext: string &optional; ##< Or here, like this.
	};

	## General documentation for a type "ComplexRecord" goes here.
	type ComplexRecord: record {
		field1: count;               ##< Counts something.
		field2: bool;                ##< Toggles something.
		field3: SimpleRecord;        ##< Zeekygen automatically tracks types
		                             ##< and cross-references are automatically
		                             ##< inserted into generated docs.
		msg: string &default="blah"; ##< Attributes are self-documenting.
	} &redef;

	## An example record to be used with a logging stream.
	## Nothing special about it.  If another script redefs this type
	## to add fields, the generated documentation will show all original
	## fields plus the extensions and the scripts which contributed to it
	## (provided they are also @load'ed).
	type Info: record {
		ts:       time       &log;
		uid:      string     &log;
		status:   count      &log &optional;
	};

	## Add documentation for "an_option" here.
	## The type/attribute information is all generated automatically.
	const an_option: set[addr, addr, string] &redef;

	## Default initialization will be generated automatically.
	const option_with_init = 0.01 secs &redef; ##< More docs can be added here.

	## Put some documentation for "a_var" here.  Any global/non-const that
	## isn't a function/event/hook is classified as a "state variable"
	## in the generated docs.
	global a_var: bool;

	## Types are inferred, that information is self-documenting.
	global var_without_explicit_type = "this works";

	## The first sentence for a particular identifier's summary text ends here.
	## And this second sentence doesn't show in the short description provided
	## by the table of all identifiers declared by this script.
	global summary_test: string;

    ## Summarize purpose of "a_function" here.
    ## Give more details about "a_function" here.
    ## Separating the documentation of the params/return values with
    ## empty comments is optional, but improves readability of script.
    ##
    ## tag: Function arguments can be described
    ##      like this.
	##
    ## msg: Another param.
    ##
    ## Returns: Describe the return type here.
    global a_function: function(tag: string, msg: string): string;

    ## Summarize "an_event" here.
    ## Give more details about "an_event" here.
	##
	## ZeekygenExample::a_function should not be confused as a parameter
	## in the generated docs, but it also doesn't generate a cross-reference
	## link.  Use the see role instead: :zeek:see:`ZeekygenExample::a_function`.
	##
    ## name: Describe the argument here.
    global an_event: event(name: string);
}

# This function isn't exported, so it won't appear anywhere in the generated
# documentation.  So using ``##``-style comments is pointless here.
function function_without_proto(tag: string): string
    {
    # Zeekygen-style comments only apply to entities at global-scope so
    # Zeekygen doesn't associate the following comments with anything.
    ##! This comment should be ignored by Zeekygen.
    ## This comment should be ignored by Zeekygen.
    ##< This comment should be ignored by Zeekygen.
    return "blah";
    }

# Same thing goes for types -- it's not exported, so it's considered
# private to this script and comments are only interesting to a person
# who is already reading the raw source for the script (so don't use
# ``##`` comments here.
type PrivateRecord: record {
    field1: bool;
    field2: count;
};

# Event handlers are also an implementation detail of a script, so they
# don't show up anywhere in the generated documentation.
event zeek_init()
    {
    }
