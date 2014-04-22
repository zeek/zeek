:doc:`/scripts/broxygen/example.bro`
    This is an example script that demonstrates Broxygen-style
    documentation.  It generally will make most sense when viewing
    the script's raw source code and comparing to the HTML-rendered
    version.
    
    Comments in the from ``##!`` are meant to summarize the script's
    purpose.  They are transferred directly in to the generated
    `reStructuredText <http://docutils.sourceforge.net/rst.html>`_
    (reST) document associated with the script.
    
    .. tip:: You can embed directives and roles within ``##``-stylized comments.
    
    There's also a custom role to reference any identifier node in
    the Bro Sphinx domain that's good for "see alsos", e.g.
    
    See also: :bro:see:`BroxygenExample::a_var`,
    :bro:see:`BroxygenExample::ONE`, :bro:see:`SSH::Info`
    
    And a custom directive does the equivalent references:
    
    .. bro:see:: BroxygenExample::a_var BroxygenExample::ONE SSH::Info

