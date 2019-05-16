:orphan:

Package: base/frameworks/config
===============================

The configuration framework provides a way to change the Zeek configuration
in "option" values at run-time.

:doc:`/scripts/base/frameworks/config/__load__.zeek`


:doc:`/scripts/base/frameworks/config/main.zeek`

   The configuration framework provides a way to change Zeek options
   (as specified by the "option" keyword) at runtime. It also logs runtime
   changes to options to config.log.

:doc:`/scripts/base/frameworks/config/input.zeek`

   File input for the configuration framework using the input framework.

:doc:`/scripts/base/frameworks/config/weird.zeek`

   This script sets up the config framework change handlers for weirds.

