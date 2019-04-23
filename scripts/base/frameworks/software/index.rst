:orphan:

Package: base/frameworks/software
=================================

The software framework provides infrastructure for maintaining a table
of software versions seen on the network. The version parsing itself
is carried out by external protocol-specific scripts that feed into
this framework.

:doc:`/scripts/base/frameworks/software/__load__.zeek`


:doc:`/scripts/base/frameworks/software/main.zeek`

   This script provides the framework for software version detection and
   parsing but doesn't actually do any detection on it's own.  It relies on
   other protocol specific scripts to parse out software from the protocols
   that they analyze.  The entry point for providing new software detections
   to this framework is through the :zeek:id:`Software::found` function.

