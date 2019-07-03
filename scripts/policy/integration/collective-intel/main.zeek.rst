:tocdepth: 3

policy/integration/collective-intel/main.zeek
=============================================
.. zeek:namespace:: Intel


:Namespace: Intel
:Imports: :doc:`base/frameworks/intel </scripts/base/frameworks/intel/index>`

Summary
~~~~~~~
Types
#####
============================================ ========================================================
:zeek:type:`Intel::CIF`: :zeek:type:`record` CIF record used for consistent formatting of CIF values.
============================================ ========================================================

Redefinitions
#############
================================================= ====================================================================================
:zeek:type:`Intel::Info`: :zeek:type:`record`     
:zeek:type:`Intel::MetaData`: :zeek:type:`record` This file adds mapping between the Collective Intelligence Framework (CIF) and Zeek.
================================================= ====================================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Types
#####
.. zeek:type:: Intel::CIF

   :Type: :zeek:type:`record`

      tags: :zeek:type:`string` :zeek:attr:`&optional` :zeek:attr:`&log`
         CIF tags observations, examples for tags are ``botnet`` or ``exploit``.

      confidence: :zeek:type:`double` :zeek:attr:`&optional` :zeek:attr:`&log`
         In CIF Confidence details the degree of certainty of a given observation.

      source: :zeek:type:`string` :zeek:attr:`&optional` :zeek:attr:`&log`
         Source given in CIF.

      description: :zeek:type:`string` :zeek:attr:`&optional` :zeek:attr:`&log`
         description given in CIF.

      firstseen: :zeek:type:`string` :zeek:attr:`&optional` :zeek:attr:`&log`
         First time the source observed the behavior.

      lastseen: :zeek:type:`string` :zeek:attr:`&optional` :zeek:attr:`&log`
         Last time the source observed the behavior.

   CIF record used for consistent formatting of CIF values.


