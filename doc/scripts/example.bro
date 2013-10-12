##! This is an example script that demonstrates documentation features.
##! Comments of the form ``##!`` are for the script summary.  The contents of
##! these comments are transferred directly into the auto-generated
##! `reStructuredText <http://docutils.sourceforge.net/rst.html>`_
##! (reST) document's summary section.
##!
##! .. tip:: You can embed directives and roles within ``##``-stylized comments.
##!
##! There's also a custom role to reference any identifier node in
##! the Bro Sphinx domain that's good for "see alsos", e.g.
##!
##! See also: :bro:see:`Example::a_var`, :bro:see:`Example::ONE`,
##! :bro:see:`SSH::Info`
##!
##! And a custom directive does the equivalent references:
##!
##! .. bro:see:: Example::a_var Example::ONE SSH::Info

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
# next declaration/identifier found in the script, but the doc framework
# will track/render identifiers regardless of whether they have any
# of these special comments associated with them.
#
# The first sentence contained within the "##"-stylized comments for
# a given identifier is special in that it will be used as summary
# text in a table containing all such identifiers and short summaries.
# If there are no sentences (text terminated with '.'), then everything
# in the "##"-stylized comments up until the first empty comment
# is taken as the summary text for a given identifier.

# @load directives are self-documenting
@load frameworks/software/vulnerable

# "module" statements are self-documenting
module Example;

# redefinitions of "capture_filters" are self-documenting and
# go into the generated documentation's "Packet Filter" section
redef capture_filters += {
    ["ssl"] = "tcp port 443",
    ["nntps"] = "tcp port 562",
};

global example_ports = {
    443/tcp, 562/tcp,
} &redef;


event bro_init()
	{
	Analyzer::register_for_ports(Analyzer::ANALYZER_SSL, example_ports);
	}

# redefinitions of "Notice::Type" are self-documenting, but
# more information can be supplied in two different ways
redef enum Notice::Type += {
    ## any number of this type of comment
    ## will document "Notice_One"
    Notice_One,
    Notice_Two,  ##< any number of this type of comment
                 ##< will document "Notice_Two"
    Notice_Three,
    Notice_Four,
};

# Redef'ing the ID enumeration for logging streams is automatically tracked.
# Comments of the "##" form can be use to further document it, but it's
# better to do all documentation related to logging in the summary section
# as is shown above.
redef enum Log::ID += { LOG };

# Anything declared in the export section will show up in the rendered
# documentation's "public interface" section

export {

    # these headings don't mean anything special to the
    # doc framework right now, I'm just including them
    # to make it more clear to the reader how the doc
    # framework will actually categorize a script's identifiers

    ############## types ################

    # Note that I'm just mixing the "##" and "##<"
    # types of comments in the following declarations
    # as a demonstration.  Normally, it would be good style
    # to pick one and be consistent.

    ## documentation for "SimpleEnum"
    ## goes here.
    type SimpleEnum: enum {
        ## and more specific info for "ONE"
        ## can span multiple lines
        ONE,
        TWO,  ##< or more info like this for "TWO"
              ##< can span multiple lines
        THREE,
    };

    ## document the "SimpleEnum" redef here
    redef enum SimpleEnum  += {
        FOUR, ##< and some documentation for "FOUR"
        ## also "FIVE" for good measure
        FIVE
    };

    ## general documentation for a type "SimpleRecord"
    ## goes here.
    type SimpleRecord: record {
        ## counts something
        field1: count;
        field2: bool; ##< toggles something
    };

    ## document the record extension redef here
    redef record SimpleRecord += {
        ## document the extending field here
        field_ext: string &optional; ##< (or here)
    };

    ## general documentation for a type "ComplexRecord" goes here
    type ComplexRecord: record {
        field1: count;               ##< counts something
        field2: bool;                ##< toggles something
        field3: SimpleRecord;
        msg: string &default="blah"; ##< attributes are self-documenting
    } &redef;

    ## An example record to be used with a logging stream.
    type Info: record {
        ts:       time       &log;
        uid:      string     &log;
        status:   count      &log &optional;
    };

    ############## options ################
    # right now, I'm just defining an option as
    # any const with &redef (something that can
    # change at parse time, but not at run time.

    ## add documentation for "an_option" here
    const an_option: set[addr, addr, string] &redef;

    # default initialization will be self-documenting
    const option_with_init = 0.01 secs &redef; ##< More docs can be added here.

    ############## state variables ############
    # right now, I'm defining this as any global
    # that's not a function/event.  doesn't matter
    # if &redef attribute is present

    ## put some documentation for "a_var" here
    global a_var: bool;

    # attributes are self-documenting
    global var_with_attr: count &persistent;

    # it's fine if the type is inferred, that information is self-documenting
    global var_without_explicit_type = "this works";

    ## The first.sentence for the summary text ends here.  And this second
    ## sentence doesn't show in the short description.
    global dummy: string;

    ############## functions/events ############

    ## Summarize purpose of "a_function" here.
    ## Give more details about "a_function" here.
    ## Separating the documentation of the params/return values with
    ## empty comments is optional, but improves readability of script.
    ##
    ## tag: function arguments can be described
    ##      like this
    ## msg: another param
    ##
    ## Returns: describe the return type here
    global a_function: function(tag: string, msg: string): string;

    ## Summarize "an_event" here.
    ## Give more details about "an_event" here.
	## Example::an_event should not be confused as a parameter.
    ## name: describe the argument here
    global an_event: event(name: string);

    ## This is a declaration of an example event that can be used in
    ## logging streams and is raised once for each log entry.
    global log_example: event(rec: Info);
}

function filter_func(rec: Info): bool
    {
    return T;
    }

# this function is documented in the "private interface" section
# of generated documentation and any "##"-stylized comments would also
# be rendered there
function function_without_proto(tag: string): string
    {
    return "blah";
    }

# this record type is documented in the "private interface" section
# of generated documentation and any "##"-stylized comments would also
# be rendered there
type PrivateRecord: record {
    field1: bool;
    field2: count;
};

event bro_init()
    {
    Log::create_stream(Example::LOG, [$columns=Info, $ev=log_example]);
    Log::add_filter(Example::LOG, [
        $name="example-filter",
        $path="example-filter",
        $pred=filter_func,
        $exclude=set("ts")
        ]);
    }
