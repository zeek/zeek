:tocdepth: 3

policy/frameworks/intel/do_notice.zeek
======================================
.. zeek:namespace:: Intel

This script enables notice generation for intelligence matches.

:Namespace: Intel
:Imports: :doc:`base/frameworks/intel </scripts/base/frameworks/intel/index>`, :doc:`base/frameworks/notice </scripts/base/frameworks/notice/index>`

Summary
~~~~~~~
Redefinitions
#############
================================================= ===================================================================================
:zeek:type:`Intel::MetaData`: :zeek:type:`record` 
                                                  
                                                  :New Fields: :zeek:type:`Intel::MetaData`
                                                  
                                                    do_notice: :zeek:type:`bool` :zeek:attr:`&default` = ``F`` :zeek:attr:`&optional`
                                                      A boolean value to allow the data itself to represent
                                                      if the indicator that this metadata is attached to
                                                      is notice worthy.
                                                  
                                                    if_in: :zeek:type:`Intel::Where` :zeek:attr:`&optional`
                                                      Restrictions on when notices are created to only create
                                                      them if the *do_notice* field is T and the notice was
                                                      seen in the indicated location.
:zeek:type:`Notice::Type`: :zeek:type:`enum`      
                                                  
                                                  * :zeek:enum:`Intel::Notice`:
                                                    This notice is generated when an intelligence
                                                    indicator is denoted to be notice-worthy.
================================================= ===================================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~

