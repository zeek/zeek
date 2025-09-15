:tocdepth: 3

base/frameworks/intel/files.zeek
================================
.. zeek:namespace:: Intel

File analysis framework integration for the intelligence framework. This
script manages file information in intelligence framework data structures.

:Namespace: Intel
:Imports: :doc:`base/frameworks/intel/main.zeek </scripts/base/frameworks/intel/main.zeek>`

Summary
~~~~~~~
Redefinitions
#############
============================================= ==============================================================================
:zeek:type:`Intel::Info`: :zeek:type:`record` Record used for the logging framework representing a positive
                                              hit within the intelligence framework.
                                              
                                              :New Fields: :zeek:type:`Intel::Info`
                                              
                                                fuid: :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`
                                                  If a file was associated with this intelligence hit,
                                                  this is the uid for the file.
                                              
                                                file_mime_type: :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`
                                                  A mime type if the intelligence hit is related to a file.
                                              
                                                file_desc: :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`
                                                  Frequently files can be "described" to give a bit more context.
:zeek:type:`Intel::Seen`: :zeek:type:`record` Information about a piece of "seen" data.
                                              
                                              :New Fields: :zeek:type:`Intel::Seen`
                                              
                                                f: :zeek:type:`fa_file` :zeek:attr:`&optional`
                                                  If the data was discovered within a file, the file record
                                                  should go here to provide context to the data.
                                              
                                                fuid: :zeek:type:`string` :zeek:attr:`&optional`
                                                  If the data was discovered within a file, the file uid should
                                                  go here to provide context to the data.
:zeek:type:`Intel::Type`: :zeek:type:`enum`   Enum type to represent various types of intelligence data.
                                              
                                              * :zeek:enum:`Intel::FILE_HASH`:
                                                File hash which is non-hash type specific.
                                              
                                              * :zeek:enum:`Intel::FILE_NAME`:
                                                File name.
============================================= ==============================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~

