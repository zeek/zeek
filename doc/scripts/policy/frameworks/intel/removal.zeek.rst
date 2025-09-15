:tocdepth: 3

policy/frameworks/intel/removal.zeek
====================================
.. zeek:namespace:: Intel

This script enables removal of intelligence items.

:Namespace: Intel
:Imports: :doc:`base/frameworks/intel </scripts/base/frameworks/intel/index>`

Summary
~~~~~~~
Redefinitions
#############
================================================= ================================================================================
:zeek:type:`Intel::MetaData`: :zeek:type:`record` 
                                                  
                                                  :New Fields: :zeek:type:`Intel::MetaData`
                                                  
                                                    remove: :zeek:type:`bool` :zeek:attr:`&default` = ``F`` :zeek:attr:`&optional`
                                                      A boolean value to indicate whether the item should be removed.
================================================= ================================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~

