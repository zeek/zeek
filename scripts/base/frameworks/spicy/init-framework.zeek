# doc-common-start
module Spicy;

export {
# doc-functions-start
    ## Enable a specific Spicy protocol analyzer if not already active. If this
    ## analyzer replaces an standard analyzer, that one will automatically be
    ## disabled.
    ##
    ## tag: analyzer to toggle
    ##
    ## Returns: true if the operation succeeded
    global enable_protocol_analyzer: function(tag: Analyzer::Tag) : bool;

    ## Disable a specific Spicy protocol analyzer if not already inactive. If
    ## this analyzer replaces an standard analyzer, that one will automatically
    ## be re-enabled.
    ##
    ## tag: analyzer to toggle
    ##
    ## Returns: true if the operation succeeded
    global disable_protocol_analyzer: function(tag: Analyzer::Tag) : bool;


    ## Enable a specific Spicy file analyzer if not already active. If this
    ## analyzer replaces an standard analyzer, that one will automatically be
    ## disabled.
    ##
    ## tag: analyzer to toggle
    ##
    ## Returns: true if the operation succeeded
    global enable_file_analyzer: function(tag: Files::Tag) : bool;

    ## Disable a specific Spicy file analyzer if not already inactive. If
    ## this analyzer replaces an standard analyzer, that one will automatically
    ## be re-enabled.
    ##
    ## tag: analyzer to toggle
    ##
    ## Returns: true if the operation succeeded
    global disable_file_analyzer: function(tag: Files::Tag) : bool;

    ## Returns current resource usage as reported by the Spicy runtime system.
    global resource_usage: function() : ResourceUsage;
# doc-functions-end
}

# Marked with &is_used to suppress complaints when there aren't any
# Spicy file analyzers loaded, and hence this event can't be generated.
# The attribute is only supported for Zeek 5.0 and higher.
event spicy_analyzer_for_mime_type(a: Files::Tag, mt: string) &is_used
    {
    Files::register_for_mime_type(a, mt);
    }

function enable_protocol_analyzer(tag: Analyzer::Tag) : bool
    {
    return Spicy::__toggle_analyzer(tag, T);
    }

function disable_protocol_analyzer(tag: Analyzer::Tag) : bool
    {
    return Spicy::__toggle_analyzer(tag, F);
    }

function enable_file_analyzer(tag: Files::Tag) : bool
    {
    return Spicy::__toggle_analyzer(tag, T);
    }

function disable_file_analyzer(tag: Files::Tag) : bool
    {
    return Spicy::__toggle_analyzer(tag, F);
    }

function resource_usage() : ResourceUsage
    {
    return Spicy::__resource_usage();
    }
