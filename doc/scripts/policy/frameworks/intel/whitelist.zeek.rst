:tocdepth: 3

policy/frameworks/intel/whitelist.zeek
======================================
.. zeek:namespace:: Intel

This script enables whitelisting for intelligence items.

:Namespace: Intel
:Imports: :doc:`base/frameworks/intel </scripts/base/frameworks/intel/index>`

Summary
~~~~~~~
Redefinitions
#############
================================================= ===================================================================================
:zeek:type:`Intel::MetaData`: :zeek:type:`record` 
                                                  
                                                  :New Fields: :zeek:type:`Intel::MetaData`
                                                  
                                                    whitelist: :zeek:type:`bool` :zeek:attr:`&default` = ``F`` :zeek:attr:`&optional`
                                                      A boolean value to indicate whether the item is whitelisted.
================================================= ===================================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~

