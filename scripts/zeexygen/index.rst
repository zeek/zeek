:orphan:

Package: zeexygen
=================

This package is loaded during the process which automatically generates
reference documentation for all Zeek scripts (i.e. "Zeexygen").  Its only
purpose is to provide an easy way to load all known Zeek scripts plus any
extra scripts needed or used by the documentation process.

:doc:`/scripts/zeexygen/__load__.zeek`


:doc:`/scripts/zeexygen/example.zeek`

   This is an example script that demonstrates Zeexygen-style
   documentation.  It generally will make most sense when viewing
   the script's raw source code and comparing to the HTML-rendered
   version.
   
   Comments in the from ``##!`` are meant to summarize the script's
   purpose.  They are transferred directly in to the generated
   `reStructuredText <http://docutils.sourceforge.net/rst.html>`_
   (reST) document associated with the script.
   
   .. tip:: You can embed directives and roles within ``##``-stylized comments.
   
   There's also a custom role to reference any identifier node in
   the Zeek Sphinx domain that's good for "see alsos", e.g.
   
   See also: :zeek:see:`ZeexygenExample::a_var`,
   :zeek:see:`ZeexygenExample::ONE`, :zeek:see:`SSH::Info`
   
   And a custom directive does the equivalent references:
   
   .. zeek:see:: ZeexygenExample::a_var ZeexygenExample::ONE SSH::Info

