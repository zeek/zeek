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
                                                  
                                                  :New Fields: :zeek:type:`Intel::Info`
                                                  
                                                    cif: :zeek:type:`Intel::CIF` :zeek:attr:`&log` :zeek:attr:`&optional`
:zeek:type:`Intel::MetaData`: :zeek:type:`record` This file adds mapping between the Collective Intelligence Framework (CIF) and Zeek.
                                                  
                                                  :New Fields: :zeek:type:`Intel::MetaData`
                                                  
                                                    cif_tags: :zeek:type:`string` :zeek:attr:`&optional`
                                                      Maps to the 'tags' fields in CIF
                                                  
                                                    cif_confidence: :zeek:type:`double` :zeek:attr:`&optional`
                                                      Maps to the 'confidence' field in CIF
                                                  
                                                    cif_source: :zeek:type:`string` :zeek:attr:`&optional`
                                                      Maps to the 'source' field in CIF
                                                  
                                                    cif_description: :zeek:type:`string` :zeek:attr:`&optional`
                                                      Maps to the 'description' field in CIF
                                                  
                                                    cif_firstseen: :zeek:type:`string` :zeek:attr:`&optional`
                                                      Maps to the 'firstseen' field in CIF
                                                  
                                                    cif_lastseen: :zeek:type:`string` :zeek:attr:`&optional`
                                                      Maps to the 'lastseen' field in CIF
================================================= ====================================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Types
#####
.. zeek:type:: Intel::CIF
   :source-code: policy/integration/collective-intel/main.zeek 24 37

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


