:tocdepth: 3

base/bif/zeek.bif.zeek
======================
.. zeek:namespace:: GLOBAL

A collection of built-in functions that implement a variety of things
such as general programming algorithms, string processing, math functions,
introspection, type conversion, file/directory manipulation, packet
filtering, interprocess communication and controlling protocol analyzer
behavior.

You'll find most of Zeek's built-in functions that aren't protocol-specific
in this file.

:Namespace: GLOBAL

Summary
~~~~~~~
Functions
#########
============================================================================================================================= ===============================================================================
:zeek:id:`active_file`: :zeek:type:`function`                                                                                 Checks whether a given file is open.
:zeek:id:`addr_to_counts`: :zeek:type:`function`                                                                              Converts an :zeek:type:`addr` to an :zeek:type:`index_vec`.
:zeek:id:`addr_to_ptr_name`: :zeek:type:`function`                                                                            Converts an IP address to a reverse pointer name.
:zeek:id:`addr_to_subnet`: :zeek:type:`function`                                                                              Converts a :zeek:type:`addr` to a :zeek:type:`subnet`.
:zeek:id:`all_set`: :zeek:type:`function`                                                                                     Tests whether *all* elements of a boolean vector (``vector of bool``) are
                                                                                                                              true.
:zeek:id:`anonymize_addr`: :zeek:type:`function`                                                                              Anonymizes an IP address.
:zeek:id:`any_set`: :zeek:type:`function`                                                                                     Tests whether a boolean vector (``vector of bool``) has *any* true
                                                                                                                              element.
:zeek:id:`bro_is_terminating`: :zeek:type:`function` :zeek:attr:`&deprecated` = ``"Remove in v3.1: use zeek_is_terminating"`` Checks if Zeek is terminating.
:zeek:id:`bro_version`: :zeek:type:`function` :zeek:attr:`&deprecated` = ``"Remove in v3.1: use zeek_version"``               Returns the Zeek version string.
:zeek:id:`bytestring_to_count`: :zeek:type:`function`                                                                         Converts a string of bytes to a :zeek:type:`count`.
:zeek:id:`bytestring_to_double`: :zeek:type:`function`                                                                        Converts a string of bytes (in network byte order) to a :zeek:type:`double`.
:zeek:id:`bytestring_to_hexstr`: :zeek:type:`function`                                                                        Converts a string of bytes into its hexadecimal representation.
:zeek:id:`calc_next_rotate`: :zeek:type:`function`                                                                            Calculates the duration until the next time a file is to be rotated, based
                                                                                                                              on a given rotate interval.
:zeek:id:`cat`: :zeek:type:`function`                                                                                         Returns the concatenation of the string representation of its arguments.
:zeek:id:`cat_sep`: :zeek:type:`function`                                                                                     Concatenates all arguments, with a separator placed between each one.
:zeek:id:`check_subnet`: :zeek:type:`function`                                                                                Checks if a specific subnet is a member of a set/table[subnet].
:zeek:id:`clear_table`: :zeek:type:`function`                                                                                 Removes all elements from a set or table.
:zeek:id:`close`: :zeek:type:`function`                                                                                       Closes an open file and flushes any buffered content.
:zeek:id:`connection_exists`: :zeek:type:`function`                                                                           Checks whether a connection is (still) active.
:zeek:id:`continue_processing`: :zeek:type:`function`                                                                         Resumes Zeek's packet processing.
:zeek:id:`convert_for_pattern`: :zeek:type:`function`                                                                         Escapes a string so that it becomes a valid :zeek:type:`pattern` and can be
                                                                                                                              used with the :zeek:id:`string_to_pattern`.
:zeek:id:`count_to_port`: :zeek:type:`function`                                                                               Converts a :zeek:type:`count` and ``transport_proto`` to a :zeek:type:`port`.
:zeek:id:`count_to_v4_addr`: :zeek:type:`function`                                                                            Converts a :zeek:type:`count` to an :zeek:type:`addr`.
:zeek:id:`counts_to_addr`: :zeek:type:`function`                                                                              Converts an :zeek:type:`index_vec` to an :zeek:type:`addr`.
:zeek:id:`current_analyzer`: :zeek:type:`function`                                                                            Returns the ID of the analyzer which raised the current event.
:zeek:id:`current_time`: :zeek:type:`function`                                                                                Returns the current wall-clock time.
:zeek:id:`decode_base64`: :zeek:type:`function`                                                                               Decodes a Base64-encoded string.
:zeek:id:`decode_base64_conn`: :zeek:type:`function`                                                                          Decodes a Base64-encoded string that was derived from processing a connection.
:zeek:id:`disable_analyzer`: :zeek:type:`function`                                                                            Disables the analyzer which raised the current event (if the analyzer
                                                                                                                              belongs to the given connection).
:zeek:id:`do_profiling`: :zeek:type:`function`                                                                                Enables detailed collection of profiling statistics.
:zeek:id:`double_to_count`: :zeek:type:`function`                                                                             Converts a :zeek:type:`double` to a :zeek:type:`count`.
:zeek:id:`double_to_interval`: :zeek:type:`function`                                                                          Converts a :zeek:type:`double` to an :zeek:type:`interval`.
:zeek:id:`double_to_time`: :zeek:type:`function`                                                                              Converts a :zeek:type:`double` value to a :zeek:type:`time`.
:zeek:id:`dump_current_packet`: :zeek:type:`function`                                                                         Writes the current packet to a file.
:zeek:id:`dump_packet`: :zeek:type:`function`                                                                                 Writes a given packet to a file.
:zeek:id:`dump_rule_stats`: :zeek:type:`function`                                                                             Write rule matcher statistics (DFA states, transitions, memory usage, cache
                                                                                                                              hits/misses) to a file.
:zeek:id:`enable_raw_output`: :zeek:type:`function`                                                                           Prevents escaping of non-ASCII characters when writing to a file.
:zeek:id:`encode_base64`: :zeek:type:`function`                                                                               Encodes a Base64-encoded string.
:zeek:id:`entropy_test_add`: :zeek:type:`function`                                                                            Adds data to an incremental entropy calculation.
:zeek:id:`entropy_test_finish`: :zeek:type:`function`                                                                         Finishes an incremental entropy calculation.
:zeek:id:`entropy_test_init`: :zeek:type:`function`                                                                           Initializes data structures for incremental entropy calculation.
:zeek:id:`enum_to_int`: :zeek:type:`function`                                                                                 Converts an :zeek:type:`enum` to an :zeek:type:`int`.
:zeek:id:`exit`: :zeek:type:`function`                                                                                        Shuts down the Zeek process immediately.
:zeek:id:`exp`: :zeek:type:`function`                                                                                         Computes the exponential function.
:zeek:id:`file_magic`: :zeek:type:`function`                                                                                  Determines the MIME type of a piece of data using Zeek's file magic
                                                                                                                              signatures.
:zeek:id:`file_mode`: :zeek:type:`function`                                                                                   Converts UNIX file permissions given by a mode to an ASCII string.
:zeek:id:`file_size`: :zeek:type:`function`                                                                                   Returns the size of a given file.
:zeek:id:`filter_subnet_table`: :zeek:type:`function`                                                                         For a set[subnet]/table[subnet], create a new table that contains all entries
                                                                                                                              that contain a given subnet.
:zeek:id:`find_entropy`: :zeek:type:`function`                                                                                Performs an entropy test on the given data.
:zeek:id:`floor`: :zeek:type:`function`                                                                                       Computes the greatest integer less than the given :zeek:type:`double` value.
:zeek:id:`flush_all`: :zeek:type:`function`                                                                                   Flushes all open files to disk.
:zeek:id:`fmt`: :zeek:type:`function`                                                                                         Produces a formatted string à la ``printf``.
:zeek:id:`fnv1a32`: :zeek:type:`function`                                                                                     Returns 32-bit digest of arbitrary input values using FNV-1a hash algorithm.
:zeek:id:`get_conn_transport_proto`: :zeek:type:`function`                                                                    Extracts the transport protocol from a connection.
:zeek:id:`get_current_packet`: :zeek:type:`function`                                                                          Returns the currently processed PCAP packet.
:zeek:id:`get_current_packet_header`: :zeek:type:`function`                                                                   Function to get the raw headers of the currently processed packet.
:zeek:id:`get_file_name`: :zeek:type:`function`                                                                               Gets the filename associated with a file handle.
:zeek:id:`get_port_transport_proto`: :zeek:type:`function`                                                                    Extracts the transport protocol from a :zeek:type:`port`.
:zeek:id:`getenv`: :zeek:type:`function`                                                                                      Returns a system environment variable.
:zeek:id:`gethostname`: :zeek:type:`function`                                                                                 Returns the hostname of the machine Zeek runs on.
:zeek:id:`getpid`: :zeek:type:`function`                                                                                      Returns Zeek's process ID.
:zeek:id:`global_ids`: :zeek:type:`function`                                                                                  Generates a table with information about all global identifiers.
:zeek:id:`global_sizes`: :zeek:type:`function`                                                                                Generates a table of the size of all global variables.
:zeek:id:`haversine_distance`: :zeek:type:`function`                                                                          Calculates distance between two geographic locations using the haversine
                                                                                                                              formula.
:zeek:id:`hexstr_to_bytestring`: :zeek:type:`function`                                                                        Converts a hex-string into its binary representation.
:zeek:id:`hrw_weight`: :zeek:type:`function`                                                                                  Calculates a weight value for use in a Rendezvous Hashing algorithm.
:zeek:id:`identify_data`: :zeek:type:`function`                                                                               Determines the MIME type of a piece of data using Zeek's file magic
                                                                                                                              signatures.
:zeek:id:`install_dst_addr_filter`: :zeek:type:`function`                                                                     Installs a filter to drop packets destined to a given IP address with
                                                                                                                              a certain probability if none of a given set of TCP flags are set.
:zeek:id:`install_dst_net_filter`: :zeek:type:`function`                                                                      Installs a filter to drop packets destined to a given subnet with
                                                                                                                              a certain probability if none of a given set of TCP flags are set.
:zeek:id:`install_src_addr_filter`: :zeek:type:`function`                                                                     Installs a filter to drop packets from a given IP source address with
                                                                                                                              a certain probability if none of a given set of TCP flags are set.
:zeek:id:`install_src_net_filter`: :zeek:type:`function`                                                                      Installs a filter to drop packets originating from a given subnet with
                                                                                                                              a certain probability if none of a given set of TCP flags are set.
:zeek:id:`int_to_count`: :zeek:type:`function`                                                                                Converts a (positive) :zeek:type:`int` to a :zeek:type:`count`.
:zeek:id:`interval_to_double`: :zeek:type:`function`                                                                          Converts an :zeek:type:`interval` to a :zeek:type:`double`.
:zeek:id:`is_external_connection`: :zeek:type:`function`                                                                      Determines whether a connection has been received externally.
:zeek:id:`is_icmp_port`: :zeek:type:`function`                                                                                Checks whether a given :zeek:type:`port` has ICMP as transport protocol.
:zeek:id:`is_local_interface`: :zeek:type:`function`                                                                          Checks whether a given IP address belongs to a local interface.
:zeek:id:`is_remote_event`: :zeek:type:`function`                                                                             Checks whether the last raised event came from a remote peer.
:zeek:id:`is_tcp_port`: :zeek:type:`function`                                                                                 Checks whether a given :zeek:type:`port` has TCP as transport protocol.
:zeek:id:`is_udp_port`: :zeek:type:`function`                                                                                 Checks whether a given :zeek:type:`port` has UDP as transport protocol.
:zeek:id:`is_v4_addr`: :zeek:type:`function`                                                                                  Returns whether an address is IPv4 or not.
:zeek:id:`is_v4_subnet`: :zeek:type:`function`                                                                                Returns whether a subnet specification is IPv4 or not.
:zeek:id:`is_v6_addr`: :zeek:type:`function`                                                                                  Returns whether an address is IPv6 or not.
:zeek:id:`is_v6_subnet`: :zeek:type:`function`                                                                                Returns whether a subnet specification is IPv6 or not.
:zeek:id:`is_valid_ip`: :zeek:type:`function`                                                                                 Checks if a string is a valid IPv4 or IPv6 address.
:zeek:id:`ln`: :zeek:type:`function`                                                                                          Computes the natural logarithm of a number.
:zeek:id:`log10`: :zeek:type:`function`                                                                                       Computes the common logarithm of a number.
:zeek:id:`lookup_ID`: :zeek:type:`function`                                                                                   Returns the value of a global identifier.
:zeek:id:`lookup_addr`: :zeek:type:`function`                                                                                 Issues an asynchronous reverse DNS lookup and delays the function result.
:zeek:id:`lookup_asn`: :zeek:type:`function`                                                                                  Performs an ASN lookup of an IP address.
:zeek:id:`lookup_connection`: :zeek:type:`function`                                                                           Returns the :zeek:type:`connection` record for a given connection identifier.
:zeek:id:`lookup_hostname`: :zeek:type:`function`                                                                             Issues an asynchronous DNS lookup and delays the function result.
:zeek:id:`lookup_hostname_txt`: :zeek:type:`function`                                                                         Issues an asynchronous TEXT DNS lookup and delays the function result.
:zeek:id:`lookup_location`: :zeek:type:`function`                                                                             Performs a geo-lookup of an IP address.
:zeek:id:`mask_addr`: :zeek:type:`function`                                                                                   Masks an address down to the number of given upper bits.
:zeek:id:`match_signatures`: :zeek:type:`function`                                                                            Manually triggers the signature engine for a given connection.
:zeek:id:`matching_subnets`: :zeek:type:`function`                                                                            Gets all subnets that contain a given subnet from a set/table[subnet].
:zeek:id:`md5_hash`: :zeek:type:`function`                                                                                    Computes the MD5 hash value of the provided list of arguments.
:zeek:id:`md5_hash_finish`: :zeek:type:`function`                                                                             Returns the final MD5 digest of an incremental hash computation.
:zeek:id:`md5_hash_init`: :zeek:type:`function`                                                                               Constructs an MD5 handle to enable incremental hash computation.
:zeek:id:`md5_hash_update`: :zeek:type:`function`                                                                             Updates the MD5 value associated with a given index.
:zeek:id:`md5_hmac`: :zeek:type:`function`                                                                                    Computes an HMAC-MD5 hash value of the provided list of arguments.
:zeek:id:`mkdir`: :zeek:type:`function`                                                                                       Creates a new directory.
:zeek:id:`mmdb_open_asn_db`: :zeek:type:`function`                                                                            Initializes MMDB for later use of lookup_asn.
:zeek:id:`mmdb_open_location_db`: :zeek:type:`function`                                                                       Initializes MMDB for later use of lookup_location.
:zeek:id:`network_time`: :zeek:type:`function`                                                                                Returns the timestamp of the last packet processed.
:zeek:id:`open`: :zeek:type:`function`                                                                                        Opens a file for writing.
:zeek:id:`open_for_append`: :zeek:type:`function`                                                                             Opens a file for writing or appending.
:zeek:id:`order`: :zeek:type:`function`                                                                                       Returns the order of the elements in a vector according to some
                                                                                                                              comparison function.
:zeek:id:`paraglob_equals`: :zeek:type:`function`                                                                             Compares two paraglobs for equality.
:zeek:id:`paraglob_init`: :zeek:type:`function`                                                                               Initializes and returns a new paraglob.
:zeek:id:`paraglob_match`: :zeek:type:`function`                                                                              Gets all the patterns inside the handle associated with an input string.
:zeek:id:`piped_exec`: :zeek:type:`function`                                                                                  Opens a program with ``popen`` and writes a given string to the returned
                                                                                                                              stream to send it to the opened process's stdin.
:zeek:id:`port_to_count`: :zeek:type:`function`                                                                               Converts a :zeek:type:`port` to a :zeek:type:`count`.
:zeek:id:`preserve_prefix`: :zeek:type:`function`                                                                             Preserves the prefix of an IP address in anonymization.
:zeek:id:`preserve_subnet`: :zeek:type:`function`                                                                             Preserves the prefix of a subnet in anonymization.
:zeek:id:`ptr_name_to_addr`: :zeek:type:`function`                                                                            Converts a reverse pointer name to an address.
:zeek:id:`rand`: :zeek:type:`function`                                                                                        Generates a random number.
:zeek:id:`raw_bytes_to_v4_addr`: :zeek:type:`function`                                                                        Converts a :zeek:type:`string` of bytes into an IPv4 address.
:zeek:id:`reading_live_traffic`: :zeek:type:`function`                                                                        Checks whether Zeek reads traffic from one or more network interfaces (as
                                                                                                                              opposed to from a network trace in a file).
:zeek:id:`reading_traces`: :zeek:type:`function`                                                                              Checks whether Zeek reads traffic from a trace file (as opposed to from a
                                                                                                                              network interface).
:zeek:id:`record_fields`: :zeek:type:`function`                                                                               Generates metadata about a record's fields.
:zeek:id:`record_type_to_vector`: :zeek:type:`function`                                                                       Converts a record type name to a vector of strings, where each element is
                                                                                                                              the name of a record field.
:zeek:id:`remask_addr`: :zeek:type:`function`                                                                                 Takes some top bits (such as a subnet address) from one address and the other
                                                                                                                              bits (intra-subnet part) from a second address and merges them to get a new
                                                                                                                              address.
:zeek:id:`rename`: :zeek:type:`function`                                                                                      Renames a file from src_f to dst_f.
:zeek:id:`resize`: :zeek:type:`function`                                                                                      Resizes a vector.
:zeek:id:`rmdir`: :zeek:type:`function`                                                                                       Removes a directory.
:zeek:id:`rotate_file`: :zeek:type:`function`                                                                                 Rotates a file.
:zeek:id:`rotate_file_by_name`: :zeek:type:`function`                                                                         Rotates a file identified by its name.
:zeek:id:`routing0_data_to_addrs`: :zeek:type:`function`                                                                      Converts the *data* field of :zeek:type:`ip6_routing` records that have
                                                                                                                              *rtype* of 0 into a vector of addresses.
:zeek:id:`same_object`: :zeek:type:`function`                                                                                 Checks whether two objects reference the same internal object.
:zeek:id:`set_buf`: :zeek:type:`function`                                                                                     Alters the buffering behavior of a file.
:zeek:id:`set_inactivity_timeout`: :zeek:type:`function`                                                                      Sets an individual inactivity timeout for a connection and thus
                                                                                                                              overrides the global inactivity timeout.
:zeek:id:`set_record_packets`: :zeek:type:`function`                                                                          Controls whether packet contents belonging to a connection should be
                                                                                                                              recorded (when ``-w`` option is provided on the command line).
:zeek:id:`setenv`: :zeek:type:`function`                                                                                      Sets a system environment variable.
:zeek:id:`sha1_hash`: :zeek:type:`function`                                                                                   Computes the SHA1 hash value of the provided list of arguments.
:zeek:id:`sha1_hash_finish`: :zeek:type:`function`                                                                            Returns the final SHA1 digest of an incremental hash computation.
:zeek:id:`sha1_hash_init`: :zeek:type:`function`                                                                              Constructs an SHA1 handle to enable incremental hash computation.
:zeek:id:`sha1_hash_update`: :zeek:type:`function`                                                                            Updates the SHA1 value associated with a given index.
:zeek:id:`sha256_hash`: :zeek:type:`function`                                                                                 Computes the SHA256 hash value of the provided list of arguments.
:zeek:id:`sha256_hash_finish`: :zeek:type:`function`                                                                          Returns the final SHA256 digest of an incremental hash computation.
:zeek:id:`sha256_hash_init`: :zeek:type:`function`                                                                            Constructs an SHA256 handle to enable incremental hash computation.
:zeek:id:`sha256_hash_update`: :zeek:type:`function`                                                                          Updates the SHA256 value associated with a given index.
:zeek:id:`skip_further_processing`: :zeek:type:`function`                                                                     Informs Zeek that it should skip any further processing of the contents of
                                                                                                                              a given connection.
:zeek:id:`sort`: :zeek:type:`function`                                                                                        Sorts a vector in place.
:zeek:id:`sqrt`: :zeek:type:`function`                                                                                        Computes the square root of a :zeek:type:`double`.
:zeek:id:`srand`: :zeek:type:`function`                                                                                       Sets the seed for subsequent :zeek:id:`rand` calls.
:zeek:id:`strftime`: :zeek:type:`function`                                                                                    Formats a given time value according to a format string.
:zeek:id:`string_to_pattern`: :zeek:type:`function`                                                                           Converts a :zeek:type:`string` into a :zeek:type:`pattern`.
:zeek:id:`strptime`: :zeek:type:`function`                                                                                    Parse a textual representation of a date/time value into a ``time`` type value.
:zeek:id:`subnet_to_addr`: :zeek:type:`function`                                                                              Converts a :zeek:type:`subnet` to an :zeek:type:`addr` by
                                                                                                                              extracting the prefix.
:zeek:id:`subnet_width`: :zeek:type:`function`                                                                                Returns the width of a :zeek:type:`subnet`.
:zeek:id:`suspend_processing`: :zeek:type:`function`                                                                          Stops Zeek's packet processing.
:zeek:id:`syslog`: :zeek:type:`function`                                                                                      Send a string to syslog.
:zeek:id:`system`: :zeek:type:`function`                                                                                      Invokes a command via the ``system`` function of the OS.
:zeek:id:`system_env`: :zeek:type:`function`                                                                                  Invokes a command via the ``system`` function of the OS with a prepared
                                                                                                                              environment.
:zeek:id:`terminate`: :zeek:type:`function`                                                                                   Gracefully shut down Zeek by terminating outstanding processing.
:zeek:id:`time_to_double`: :zeek:type:`function`                                                                              Converts a :zeek:type:`time` value to a :zeek:type:`double`.
:zeek:id:`to_addr`: :zeek:type:`function`                                                                                     Converts a :zeek:type:`string` to an :zeek:type:`addr`.
:zeek:id:`to_count`: :zeek:type:`function`                                                                                    Converts a :zeek:type:`string` to a :zeek:type:`count`.
:zeek:id:`to_double`: :zeek:type:`function`                                                                                   Converts a :zeek:type:`string` to a :zeek:type:`double`.
:zeek:id:`to_int`: :zeek:type:`function`                                                                                      Converts a :zeek:type:`string` to an :zeek:type:`int`.
:zeek:id:`to_json`: :zeek:type:`function`                                                                                     A function to convert arbitrary Zeek data into a JSON string.
:zeek:id:`to_port`: :zeek:type:`function`                                                                                     Converts a :zeek:type:`string` to a :zeek:type:`port`.
:zeek:id:`to_subnet`: :zeek:type:`function`                                                                                   Converts a :zeek:type:`string` to a :zeek:type:`subnet`.
:zeek:id:`type_name`: :zeek:type:`function`                                                                                   Returns the type name of an arbitrary Zeek variable.
:zeek:id:`uninstall_dst_addr_filter`: :zeek:type:`function`                                                                   Removes a destination address filter.
:zeek:id:`uninstall_dst_net_filter`: :zeek:type:`function`                                                                    Removes a destination subnet filter.
:zeek:id:`uninstall_src_addr_filter`: :zeek:type:`function`                                                                   Removes a source address filter.
:zeek:id:`uninstall_src_net_filter`: :zeek:type:`function`                                                                    Removes a source subnet filter.
:zeek:id:`unique_id`: :zeek:type:`function`                                                                                   Creates an identifier that is unique with high probability.
:zeek:id:`unique_id_from`: :zeek:type:`function`                                                                              Creates an identifier that is unique with high probability.
:zeek:id:`unlink`: :zeek:type:`function`                                                                                      Removes a file from a directory.
:zeek:id:`uuid_to_string`: :zeek:type:`function`                                                                              Converts a bytes representation of a UUID into its string form.
:zeek:id:`val_size`: :zeek:type:`function`                                                                                    Returns the number of bytes that a value occupies in memory.
:zeek:id:`write_file`: :zeek:type:`function`                                                                                  Writes data to an open file.
:zeek:id:`zeek_is_terminating`: :zeek:type:`function`                                                                         Checks if Zeek is terminating.
:zeek:id:`zeek_version`: :zeek:type:`function`                                                                                Returns the Zeek version string.
============================================================================================================================= ===============================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Functions
#########
.. zeek:id:: active_file

   :Type: :zeek:type:`function` (f: :zeek:type:`file`) : :zeek:type:`bool`

   Checks whether a given file is open.
   

   :f: The file to check.
   

   :returns: True if *f* is an open :zeek:type:`file`.
   
   .. todo:: Rename to ``is_open``.

.. zeek:id:: addr_to_counts

   :Type: :zeek:type:`function` (a: :zeek:type:`addr`) : :zeek:type:`index_vec`

   Converts an :zeek:type:`addr` to an :zeek:type:`index_vec`.
   

   :a: The address to convert into a vector of counts.
   

   :returns: A vector containing the host-order address representation,
            four elements in size for IPv6 addresses, or one element for IPv4.
   
   .. zeek:see:: counts_to_addr

.. zeek:id:: addr_to_ptr_name

   :Type: :zeek:type:`function` (a: :zeek:type:`addr`) : :zeek:type:`string`

   Converts an IP address to a reverse pointer name. For example,
   ``192.168.0.1`` to ``1.0.168.192.in-addr.arpa``.
   

   :a: The IP address to convert to a reverse pointer name.
   

   :returns: The reverse pointer representation of *a*.
   
   .. zeek:see:: ptr_name_to_addr to_addr

.. zeek:id:: addr_to_subnet

   :Type: :zeek:type:`function` (a: :zeek:type:`addr`) : :zeek:type:`subnet`

   Converts a :zeek:type:`addr` to a :zeek:type:`subnet`.
   

   :a: The address to convert.
   

   :returns: The address as a :zeek:type:`subnet`.
   
   .. zeek:see:: to_subnet

.. zeek:id:: all_set

   :Type: :zeek:type:`function` (v: :zeek:type:`any`) : :zeek:type:`bool`

   Tests whether *all* elements of a boolean vector (``vector of bool``) are
   true.
   

   :v: The boolean vector instance.
   

   :returns: True iff all elements in *v* are true or there are no elements.
   
   .. zeek:see:: any_set
   
   .. note::
   
        Missing elements count as false.

.. zeek:id:: anonymize_addr

   :Type: :zeek:type:`function` (a: :zeek:type:`addr`, cl: :zeek:type:`IPAddrAnonymizationClass`) : :zeek:type:`addr`

   Anonymizes an IP address.
   

   :a: The address to anonymize.
   

   :cl: The anonymization class, which can take on three different values:
   
       - ``ORIG_ADDR``: Tag *a* as an originator address.
   
       - ``RESP_ADDR``: Tag *a* as an responder address.
   
       - ``OTHER_ADDR``: Tag *a* as an arbitrary address.
   

   :returns: An anonymized version of *a*.
   
   .. zeek:see:: preserve_prefix preserve_subnet
   
   .. todo:: Currently dysfunctional.

.. zeek:id:: any_set

   :Type: :zeek:type:`function` (v: :zeek:type:`any`) : :zeek:type:`bool`

   Tests whether a boolean vector (``vector of bool``) has *any* true
   element.
   

   :v: The boolean vector instance.
   

   :returns: True if any element in *v* is true.
   
   .. zeek:see:: all_set

.. zeek:id:: bro_is_terminating

   :Type: :zeek:type:`function` () : :zeek:type:`bool`
   :Attributes: :zeek:attr:`&deprecated` = ``"Remove in v3.1: use zeek_is_terminating"``

   Checks if Zeek is terminating.  This function is deprecated, use
   :zeek:see:`zeek_is_terminating` instead.
   

   :returns: True if Zeek is in the process of shutting down.
   
   .. zeek:see:: terminate

.. zeek:id:: bro_version

   :Type: :zeek:type:`function` () : :zeek:type:`string`
   :Attributes: :zeek:attr:`&deprecated` = ``"Remove in v3.1: use zeek_version"``

   Returns the Zeek version string.  This function is deprecated, use
   :zeek:see:`zeek_version` instead.
   

   :returns: Zeek's version, e.g., 2.0-beta-47-debug.

.. zeek:id:: bytestring_to_count

   :Type: :zeek:type:`function` (s: :zeek:type:`string`, is_le: :zeek:type:`bool` :zeek:attr:`&default` = ``F`` :zeek:attr:`&optional`) : :zeek:type:`count`

   Converts a string of bytes to a :zeek:type:`count`.
   

   :s: A string of bytes containing the binary representation of the value.
   

   :is_le: If true, *s* is assumed to be in little endian format, else it's big endian.
   

   :returns: The value contained in *s*, or 0 if the conversion failed.
   

.. zeek:id:: bytestring_to_double

   :Type: :zeek:type:`function` (s: :zeek:type:`string`) : :zeek:type:`double`

   Converts a string of bytes (in network byte order) to a :zeek:type:`double`.
   

   :s: A string of bytes containing the binary representation of a double value.
   

   :returns: The double value contained in *s*, or 0 if the conversion
            failed.
   

.. zeek:id:: bytestring_to_hexstr

   :Type: :zeek:type:`function` (bytestring: :zeek:type:`string`) : :zeek:type:`string`

   Converts a string of bytes into its hexadecimal representation.
   For example, ``"04"`` would be converted to ``"3034"``.
   

   :bytestring: The string of bytes.
   

   :returns: The hexadecimal representation of *bytestring*.
   
   .. zeek:see:: hexdump hexstr_to_bytestring

.. zeek:id:: calc_next_rotate

   :Type: :zeek:type:`function` (i: :zeek:type:`interval`) : :zeek:type:`interval`

   Calculates the duration until the next time a file is to be rotated, based
   on a given rotate interval.
   

   :i: The rotate interval to base the calculation on.
   

   :returns: The duration until the next file rotation time.
   
   .. zeek:see:: rotate_file rotate_file_by_name

.. zeek:id:: cat

   :Type: :zeek:type:`function` (...) : :zeek:type:`string`

   Returns the concatenation of the string representation of its arguments. The
   arguments can be of any type. For example, ``cat("foo", 3, T)`` returns
   ``"foo3T"``.
   

   :returns: A string concatentation of all arguments.

.. zeek:id:: cat_sep

   :Type: :zeek:type:`function` (...) : :zeek:type:`string`

   Concatenates all arguments, with a separator placed between each one. This
   function is similar to :zeek:id:`cat`, but places a separator between each
   given argument. If any of the variable arguments is an empty string it is
   replaced by a given default string instead.
   

   :sep: The separator to place between each argument.
   

   :def: The default string to use when an argument is the empty string.
   

   :returns: A concatenation of all arguments with *sep* between each one and
            empty strings replaced with *def*.
   
   .. zeek:see:: cat string_cat

.. zeek:id:: check_subnet

   :Type: :zeek:type:`function` (search: :zeek:type:`subnet`, t: :zeek:type:`any`) : :zeek:type:`bool`

   Checks if a specific subnet is a member of a set/table[subnet].
   In contrast to the ``in`` operator, this performs an exact match, not
   a longest prefix match.
   

   :search: the subnet to search for.
   

   :t: the set[subnet] or table[subnet].
   

   :returns: True if the exact subnet is a member, false otherwise.

.. zeek:id:: clear_table

   :Type: :zeek:type:`function` (v: :zeek:type:`any`) : :zeek:type:`any`

   Removes all elements from a set or table.
   

   :v: The set or table

.. zeek:id:: close

   :Type: :zeek:type:`function` (f: :zeek:type:`file`) : :zeek:type:`bool`

   Closes an open file and flushes any buffered content.
   

   :f: A :zeek:type:`file` handle to an open file.
   

   :returns: True on success.
   
   .. zeek:see:: active_file open open_for_append write_file
                get_file_name set_buf flush_all mkdir enable_raw_output
                rmdir unlink rename

.. zeek:id:: connection_exists

   :Type: :zeek:type:`function` (c: :zeek:type:`conn_id`) : :zeek:type:`bool`

   Checks whether a connection is (still) active.
   

   :c: The connection id to check.
   

   :returns: True if the connection identified by *c* exists.
   
   .. zeek:see:: lookup_connection

.. zeek:id:: continue_processing

   :Type: :zeek:type:`function` () : :zeek:type:`any`

   Resumes Zeek's packet processing.
   
   .. zeek:see:: suspend_processing

.. zeek:id:: convert_for_pattern

   :Type: :zeek:type:`function` (s: :zeek:type:`string`) : :zeek:type:`string`

   Escapes a string so that it becomes a valid :zeek:type:`pattern` and can be
   used with the :zeek:id:`string_to_pattern`. Any character from the set
   ``^$-:"\/|*+?.(){}[]`` is prefixed with a ``\``.
   

   :s: The string to escape.
   

   :returns: An escaped version of *s* that has the structure of a valid
            :zeek:type:`pattern`.
   
   .. zeek:see:: string_to_pattern
   

.. zeek:id:: count_to_port

   :Type: :zeek:type:`function` (num: :zeek:type:`count`, proto: :zeek:type:`transport_proto`) : :zeek:type:`port`

   Converts a :zeek:type:`count` and ``transport_proto`` to a :zeek:type:`port`.
   

   :num: The :zeek:type:`port` number.
   

   :proto: The transport protocol.
   

   :returns: The :zeek:type:`count` *num* as :zeek:type:`port`.
   
   .. zeek:see:: port_to_count

.. zeek:id:: count_to_v4_addr

   :Type: :zeek:type:`function` (ip: :zeek:type:`count`) : :zeek:type:`addr`

   Converts a :zeek:type:`count` to an :zeek:type:`addr`.
   

   :ip: The :zeek:type:`count` to convert.
   

   :returns: The :zeek:type:`count` *ip* as :zeek:type:`addr`.
   
   .. zeek:see:: raw_bytes_to_v4_addr to_addr to_subnet

.. zeek:id:: counts_to_addr

   :Type: :zeek:type:`function` (v: :zeek:type:`index_vec`) : :zeek:type:`addr`

   Converts an :zeek:type:`index_vec` to an :zeek:type:`addr`.
   

   :v: The vector containing host-order IP address representation,
      one element for IPv4 addresses, four elements for IPv6 addresses.
   

   :returns: An IP address.
   
   .. zeek:see:: addr_to_counts

.. zeek:id:: current_analyzer

   :Type: :zeek:type:`function` () : :zeek:type:`count`

   Returns the ID of the analyzer which raised the current event.
   

   :returns: The ID of the analyzer which raised the current event, or 0 if
            none.

.. zeek:id:: current_time

   :Type: :zeek:type:`function` () : :zeek:type:`time`

   Returns the current wall-clock time.
   
   In general, you should use :zeek:id:`network_time` instead
   unless you are using Zeek for non-networking uses (such as general
   scripting; not particularly recommended), because otherwise your script
   may behave very differently on live traffic versus played-back traffic
   from a save file.
   

   :returns: The wall-clock time.
   
   .. zeek:see:: network_time

.. zeek:id:: decode_base64

   :Type: :zeek:type:`function` (s: :zeek:type:`string`, a: :zeek:type:`string` :zeek:attr:`&default` = ``""`` :zeek:attr:`&optional`) : :zeek:type:`string`

   Decodes a Base64-encoded string.
   

   :s: The Base64-encoded string.
   

   :a: An optional custom alphabet. The empty string indicates the default
      alphabet. If given, the string must consist of 64 unique characters.
   

   :returns: The decoded version of *s*.
   
   .. zeek:see:: decode_base64_conn encode_base64

.. zeek:id:: decode_base64_conn

   :Type: :zeek:type:`function` (cid: :zeek:type:`conn_id`, s: :zeek:type:`string`, a: :zeek:type:`string` :zeek:attr:`&default` = ``""`` :zeek:attr:`&optional`) : :zeek:type:`string`

   Decodes a Base64-encoded string that was derived from processing a connection.
   If an error is encountered decoding the string, that will be logged to
   ``weird.log`` with the associated connection.
   

   :cid: The identifier of the connection that the encoding originates from.
   

   :s: The Base64-encoded string.
   

   :a: An optional custom alphabet. The empty string indicates the default
      alphabet. If given, the string must consist of 64 unique characters.
   

   :returns: The decoded version of *s*.
   
   .. zeek:see:: decode_base64

.. zeek:id:: disable_analyzer

   :Type: :zeek:type:`function` (cid: :zeek:type:`conn_id`, aid: :zeek:type:`count`, err_if_no_conn: :zeek:type:`bool` :zeek:attr:`&default` = ``T`` :zeek:attr:`&optional`) : :zeek:type:`bool`

   Disables the analyzer which raised the current event (if the analyzer
   belongs to the given connection).
   

   :cid: The connection identifier.
   

   :aid: The analyzer ID.
   

   :returns: True if the connection identified by *cid* exists and has analyzer
            *aid*.
   
   .. zeek:see:: Analyzer::schedule_analyzer Analyzer::name

.. zeek:id:: do_profiling

   :Type: :zeek:type:`function` () : :zeek:type:`any`

   Enables detailed collection of profiling statistics. Statistics include
   CPU/memory usage, connections, TCP states/reassembler, DNS lookups,
   timers, and script-level state. The script variable :zeek:id:`profiling_file`
   holds the name of the file.
   
   .. zeek:see:: get_conn_stats
                get_dns_stats
                get_event_stats
                get_file_analysis_stats
                get_gap_stats
                get_matcher_stats
                get_net_stats
                get_proc_stats
                get_reassembler_stats
                get_thread_stats
                get_timer_stats

.. zeek:id:: double_to_count

   :Type: :zeek:type:`function` (d: :zeek:type:`double`) : :zeek:type:`count`

   Converts a :zeek:type:`double` to a :zeek:type:`count`.
   

   :d: The :zeek:type:`double` to convert.
   

   :returns: The :zeek:type:`double` *d* as unsigned integer, or 0 if *d* < 0.0.
   
   .. zeek:see:: double_to_time

.. zeek:id:: double_to_interval

   :Type: :zeek:type:`function` (d: :zeek:type:`double`) : :zeek:type:`interval`

   Converts a :zeek:type:`double` to an :zeek:type:`interval`.
   

   :d: The :zeek:type:`double` to convert.
   

   :returns: The :zeek:type:`double` *d* as :zeek:type:`interval`.
   
   .. zeek:see:: interval_to_double

.. zeek:id:: double_to_time

   :Type: :zeek:type:`function` (d: :zeek:type:`double`) : :zeek:type:`time`

   Converts a :zeek:type:`double` value to a :zeek:type:`time`.
   

   :d: The :zeek:type:`double` to convert.
   

   :returns: The :zeek:type:`double` value *d* as :zeek:type:`time`.
   
   .. zeek:see:: time_to_double double_to_count

.. zeek:id:: dump_current_packet

   :Type: :zeek:type:`function` (file_name: :zeek:type:`string`) : :zeek:type:`bool`

   Writes the current packet to a file.
   

   :file_name: The name of the file to write the packet to.
   

   :returns: True on success.
   
   .. zeek:see:: dump_packet get_current_packet

.. zeek:id:: dump_packet

   :Type: :zeek:type:`function` (pkt: :zeek:type:`pcap_packet`, file_name: :zeek:type:`string`) : :zeek:type:`bool`

   Writes a given packet to a file.
   

   :pkt: The PCAP packet.
   

   :file_name: The name of the file to write *pkt* to.
   

   :returns: True on success
   
   .. zeek:see:: get_current_packet dump_current_packet

.. zeek:id:: dump_rule_stats

   :Type: :zeek:type:`function` (f: :zeek:type:`file`) : :zeek:type:`bool`

   Write rule matcher statistics (DFA states, transitions, memory usage, cache
   hits/misses) to a file.
   

   :f: The file to write to.
   

   :returns: True (unconditionally).
   
   .. zeek:see:: get_matcher_stats

.. zeek:id:: enable_raw_output

   :Type: :zeek:type:`function` (f: :zeek:type:`file`) : :zeek:type:`any`

   Prevents escaping of non-ASCII characters when writing to a file.
   This function is equivalent to :zeek:attr:`&raw_output`.
   

   :f: The file to disable raw output for.

.. zeek:id:: encode_base64

   :Type: :zeek:type:`function` (s: :zeek:type:`string`, a: :zeek:type:`string` :zeek:attr:`&default` = ``""`` :zeek:attr:`&optional`) : :zeek:type:`string`

   Encodes a Base64-encoded string.
   

   :s: The string to encode.
   

   :a: An optional custom alphabet. The empty string indicates the default
      alphabet. If given, the string must consist of 64 unique characters.
   

   :returns: The encoded version of *s*.
   
   .. zeek:see:: decode_base64

.. zeek:id:: entropy_test_add

   :Type: :zeek:type:`function` (handle: :zeek:type:`opaque` of entropy, data: :zeek:type:`string`) : :zeek:type:`bool`

   Adds data to an incremental entropy calculation.
   

   :handle: The opaque handle representing the entropy calculation state.
   

   :data: The data to add to the entropy calculation.
   

   :returns: True on success.
   
   .. zeek:see:: find_entropy entropy_test_add entropy_test_finish

.. zeek:id:: entropy_test_finish

   :Type: :zeek:type:`function` (handle: :zeek:type:`opaque` of entropy) : :zeek:type:`entropy_test_result`

   Finishes an incremental entropy calculation. Before using this function,
   one needs to obtain an opaque handle with :zeek:id:`entropy_test_init` and
   add data to it via :zeek:id:`entropy_test_add`.
   

   :handle: The opaque handle representing the entropy calculation state.
   

   :returns: The result of the entropy test. See :zeek:id:`find_entropy` for a
            description of the individual components.
   
   .. zeek:see:: find_entropy entropy_test_init entropy_test_add

.. zeek:id:: entropy_test_init

   :Type: :zeek:type:`function` () : :zeek:type:`opaque` of entropy

   Initializes data structures for incremental entropy calculation.
   

   :returns: An opaque handle to be used in subsequent operations.
   
   .. zeek:see:: find_entropy entropy_test_add entropy_test_finish

.. zeek:id:: enum_to_int

   :Type: :zeek:type:`function` (e: :zeek:type:`any`) : :zeek:type:`int`

   Converts an :zeek:type:`enum` to an :zeek:type:`int`.
   

   :e: The :zeek:type:`enum` to convert.
   

   :returns: The :zeek:type:`int` value that corresponds to the :zeek:type:`enum`.

.. zeek:id:: exit

   :Type: :zeek:type:`function` (code: :zeek:type:`int`) : :zeek:type:`any`

   Shuts down the Zeek process immediately.
   

   :code: The exit code to return with.
   
   .. zeek:see:: terminate

.. zeek:id:: exp

   :Type: :zeek:type:`function` (d: :zeek:type:`double`) : :zeek:type:`double`

   Computes the exponential function.
   

   :d: The argument to the exponential function.
   

   :returns: *e* to the power of *d*.
   
   .. zeek:see:: floor sqrt ln log10

.. zeek:id:: file_magic

   :Type: :zeek:type:`function` (data: :zeek:type:`string`) : :zeek:type:`mime_matches`

   Determines the MIME type of a piece of data using Zeek's file magic
   signatures.
   

   :data: The data for which to find matching MIME types.
   

   :returns: All matching signatures, in order of strength.
   
   .. zeek:see:: identify_data

.. zeek:id:: file_mode

   :Type: :zeek:type:`function` (mode: :zeek:type:`count`) : :zeek:type:`string`

   Converts UNIX file permissions given by a mode to an ASCII string.
   

   :mode: The permissions (an octal number like 0644 converted to decimal).
   

   :returns: A string representation of *mode* in the format
            ``rw[xsS]rw[xsS]rw[xtT]``.

.. zeek:id:: file_size

   :Type: :zeek:type:`function` (f: :zeek:type:`string`) : :zeek:type:`double`

   Returns the size of a given file.
   

   :f: The name of the file whose size to lookup.
   

   :returns: The size of *f* in bytes.

.. zeek:id:: filter_subnet_table

   :Type: :zeek:type:`function` (search: :zeek:type:`subnet`, t: :zeek:type:`any`) : :zeek:type:`any`

   For a set[subnet]/table[subnet], create a new table that contains all entries
   that contain a given subnet.
   

   :search: the subnet to search for.
   

   :t: the set[subnet] or table[subnet].
   

   :returns: A new table that contains all the entries that cover the subnet searched for.

.. zeek:id:: find_entropy

   :Type: :zeek:type:`function` (data: :zeek:type:`string`) : :zeek:type:`entropy_test_result`

   Performs an entropy test on the given data.
   See http://www.fourmilab.ch/random.
   

   :data: The data to compute the entropy for.
   

   :returns: The result of the entropy test, which contains the following
            fields.
   
                - ``entropy``: The information density expressed as a number of
                  bits per character.
   
                - ``chi_square``: The chi-square test value expressed as an
                  absolute number and a percentage which indicates how
                  frequently a truly random sequence would exceed the value
                  calculated, i.e., the degree to which the sequence tested is
                  suspected of being non-random.
   
                  If the percentage is greater than 99% or less than 1%, the
                  sequence is almost certainly not random. If the percentage is
                  between 99% and 95% or between 1% and 5%, the sequence is
                  suspect. Percentages between 90\% and 95\% and 5\% and 10\%
                  indicate the sequence is "almost suspect."
   
                - ``mean``: The arithmetic mean of all the bytes. If the data
                  are close to random, it should be around 127.5.
   
                - ``monte_carlo_pi``: Each successive sequence of six bytes is
                  used as 24-bit *x* and *y* coordinates within a square. If
                  the distance of the randomly-generated point is less than the
                  radius of a circle inscribed within the square, the six-byte
                  sequence is considered a "hit." The percentage of hits can
                  be used to calculate the value of pi. For very large streams
                  the value will approach the correct value of pi if the
                  sequence is close to random.
   
                - ``serial_correlation``: This quantity measures the extent to
                  which each byte in the file depends upon the previous byte.
                  For random sequences this value will be close to zero.
   
   .. zeek:see:: entropy_test_init entropy_test_add entropy_test_finish

.. zeek:id:: floor

   :Type: :zeek:type:`function` (d: :zeek:type:`double`) : :zeek:type:`double`

   Computes the greatest integer less than the given :zeek:type:`double` value.
   For example, ``floor(3.14)`` returns ``3.0``, and ``floor(-3.14)``
   returns ``-4.0``.
   

   :d: The :zeek:type:`double` to manipulate.
   

   :returns: The next lowest integer of *d* as :zeek:type:`double`.
   
   .. zeek:see:: sqrt exp ln log10

.. zeek:id:: flush_all

   :Type: :zeek:type:`function` () : :zeek:type:`bool`

   Flushes all open files to disk.
   

   :returns: True on success.
   
   .. zeek:see:: active_file open open_for_append close
                get_file_name write_file set_buf mkdir enable_raw_output
                rmdir unlink rename

.. zeek:id:: fmt

   :Type: :zeek:type:`function` (...) : :zeek:type:`string`

   Produces a formatted string à la ``printf``. The first argument is the
   *format string* and specifies how subsequent arguments are converted for
   output. It is composed of zero or more directives: ordinary characters (not
   ``%``), which are copied unchanged to the output, and conversion
   specifications, each of which fetches zero or more subsequent arguments.
   Conversion specifications begin with ``%`` and the arguments must properly
   correspond to the specifier. After the ``%``, the following characters
   may appear in sequence:
   
      - ``%``: Literal ``%``
   
      - ``-``: Left-align field
   
      - ``[0-9]+``: The field width (< 128)
   
      - ``.``: Precision of floating point specifiers ``[efg]`` (< 128)
   
      - ``[DTdxsefg]``: Format specifier
   
          - ``[DT]``: ISO timestamp with microsecond precision
   
          - ``d``: Signed/Unsigned integer (using C-style ``%lld``/``%llu``
                   for ``int``/``count``)
   
          - ``x``: Unsigned hexadecimal (using C-style ``%llx``);
                   addresses/ports are converted to host-byte order
   
          - ``s``: String (byte values less than 32 or greater than 126
                   will be escaped)
   
          - ``[efg]``: Double
   

   :returns: Returns the formatted string. Given no arguments, :zeek:id:`fmt`
            returns an empty string. Given no format string or the wrong
            number of additional arguments for the given format specifier,
            :zeek:id:`fmt` generates a run-time error.
   
   .. zeek:see:: cat cat_sep string_cat

.. zeek:id:: fnv1a32

   :Type: :zeek:type:`function` (input: :zeek:type:`any`) : :zeek:type:`count`

   Returns 32-bit digest of arbitrary input values using FNV-1a hash algorithm.
   See `<https://en.wikipedia.org/wiki/Fowler%E2%80%93Noll%E2%80%93Vo_hash_function>`_.
   

   :input: The desired input value to hash.
   

   :returns: The hashed value.
   
   .. zeek:see:: hrw_weight

.. zeek:id:: get_conn_transport_proto

   :Type: :zeek:type:`function` (cid: :zeek:type:`conn_id`) : :zeek:type:`transport_proto`

   Extracts the transport protocol from a connection.
   

   :cid: The connection identifier.
   

   :returns: The transport protocol of the connection identified by *cid*.
   
   .. zeek:see:: get_port_transport_proto
                get_orig_seq get_resp_seq

.. zeek:id:: get_current_packet

   :Type: :zeek:type:`function` () : :zeek:type:`pcap_packet`

   Returns the currently processed PCAP packet.
   

   :returns: The currently processed packet, which is a record
            containing the timestamp, ``snaplen``, and packet data.
   
   .. zeek:see:: dump_current_packet dump_packet

.. zeek:id:: get_current_packet_header

   :Type: :zeek:type:`function` () : :zeek:type:`raw_pkt_hdr`

   Function to get the raw headers of the currently processed packet.
   

   :returns: The :zeek:type:`raw_pkt_hdr` record containing the Layer 2, 3 and
            4 headers of the currently processed packet.
   
   .. zeek:see:: raw_pkt_hdr get_current_packet

.. zeek:id:: get_file_name

   :Type: :zeek:type:`function` (f: :zeek:type:`file`) : :zeek:type:`string`

   Gets the filename associated with a file handle.
   

   :f: The file handle to inquire the name for.
   

   :returns: The filename associated with *f*.
   
   .. zeek:see:: open

.. zeek:id:: get_port_transport_proto

   :Type: :zeek:type:`function` (p: :zeek:type:`port`) : :zeek:type:`transport_proto`

   Extracts the transport protocol from a :zeek:type:`port`.
   

   :p: The port.
   

   :returns: The transport protocol of the port *p*.
   
   .. zeek:see:: get_conn_transport_proto
                get_orig_seq get_resp_seq

.. zeek:id:: getenv

   :Type: :zeek:type:`function` (var: :zeek:type:`string`) : :zeek:type:`string`

   Returns a system environment variable.
   

   :var: The name of the variable whose value to request.
   

   :returns: The system environment variable identified by *var*, or an empty
            string if it is not defined.
   
   .. zeek:see:: setenv

.. zeek:id:: gethostname

   :Type: :zeek:type:`function` () : :zeek:type:`string`

   Returns the hostname of the machine Zeek runs on.
   

   :returns: The hostname of the machine Zeek runs on.

.. zeek:id:: getpid

   :Type: :zeek:type:`function` () : :zeek:type:`count`

   Returns Zeek's process ID.
   

   :returns: Zeek's process ID.

.. zeek:id:: global_ids

   :Type: :zeek:type:`function` () : :zeek:type:`id_table`

   Generates a table with information about all global identifiers. The table
   value is a record containing the type name of the identifier, whether it is
   exported, a constant, an enum constant, redefinable, and its value (if it
   has one).
   

   :returns: A table that maps identifier names to information about them.
   
   .. zeek:see:: global_sizes

.. zeek:id:: global_sizes

   :Type: :zeek:type:`function` () : :zeek:type:`var_sizes`

   Generates a table of the size of all global variables. The table index is
   the variable name and the value is the variable size in bytes.
   

   :returns: A table that maps variable names to their sizes.
   
   .. zeek:see:: global_ids

.. zeek:id:: haversine_distance

   :Type: :zeek:type:`function` (lat1: :zeek:type:`double`, long1: :zeek:type:`double`, lat2: :zeek:type:`double`, long2: :zeek:type:`double`) : :zeek:type:`double`

   Calculates distance between two geographic locations using the haversine
   formula.  Latitudes and longitudes must be given in degrees, where southern
   hemispere latitudes are negative and western hemisphere longitudes are
   negative.
   

   :lat1: Latitude (in degrees) of location 1.
   

   :long1: Longitude (in degrees) of location 1.
   

   :lat2: Latitude (in degrees) of location 2.
   

   :long2: Longitude (in degrees) of location 2.
   

   :returns: Distance in miles.
   
   .. zeek:see:: haversine_distance_ip

.. zeek:id:: hexstr_to_bytestring

   :Type: :zeek:type:`function` (hexstr: :zeek:type:`string`) : :zeek:type:`string`

   Converts a hex-string into its binary representation.
   For example, ``"3034"`` would be converted to ``"04"``.
   
   The input string is assumed to contain an even number of hexadecimal digits
   (0-9, a-f, or A-F), otherwise behavior is undefined.
   

   :hexstr: The hexadecimal string representation.
   

   :returns: The binary representation of *hexstr*.
   
   .. zeek:see:: hexdump bytestring_to_hexstr

.. zeek:id:: hrw_weight

   :Type: :zeek:type:`function` (key_digest: :zeek:type:`count`, site_id: :zeek:type:`count`) : :zeek:type:`count`

   Calculates a weight value for use in a Rendezvous Hashing algorithm.
   See `<https://en.wikipedia.org/wiki/Rendezvous_hashing>`_.
   The weight function used is the one recommended in the original

   :paper: `<http://www.eecs.umich.edu/techreports/cse/96/CSE-TR-316-96.pdf>`_.
   

   :key_digest: A 32-bit digest of a key.  E.g. use :zeek:see:`fnv1a32` to
               produce this.
   

   :site_id: A 32-bit site/node identifier.
   

   :returns: The weight value for the key/site pair.
   
   .. zeek:see:: fnv1a32

.. zeek:id:: identify_data

   :Type: :zeek:type:`function` (data: :zeek:type:`string`, return_mime: :zeek:type:`bool` :zeek:attr:`&default` = ``T`` :zeek:attr:`&optional`) : :zeek:type:`string`

   Determines the MIME type of a piece of data using Zeek's file magic
   signatures.
   

   :data: The data to find the MIME type for.
   

   :return_mime: Deprecated argument; does nothing, except emit a warning
                when false.
   

   :returns: The MIME type of *data*, or "<unknown>" if there was an error
            or no match.  This is the strongest signature match.
   
   .. zeek:see:: file_magic

.. zeek:id:: install_dst_addr_filter

   :Type: :zeek:type:`function` (ip: :zeek:type:`addr`, tcp_flags: :zeek:type:`count`, prob: :zeek:type:`double`) : :zeek:type:`bool`

   Installs a filter to drop packets destined to a given IP address with
   a certain probability if none of a given set of TCP flags are set.
   Note that for IPv6 packets with a routing type header and non-zero
   segments left, this filters out against the final destination of the
   packet according to the routing extension header.
   

   :ip: Drop packets to this IP address.
   

   :tcp_flags: If none of these TCP flags are set, drop packets to *ip* with
              probability *prob*.
   

   :prob: The probability [0.0, 1.0] used to drop packets to *ip*.
   

   :returns: True (unconditionally).
   
   .. zeek:see:: Pcap::precompile_pcap_filter
                Pcap::install_pcap_filter
                install_src_addr_filter
                install_src_net_filter
                uninstall_src_addr_filter
                uninstall_src_net_filter
                install_dst_net_filter
                uninstall_dst_addr_filter
                uninstall_dst_net_filter
                Pcap::error
   
   .. todo:: The return value should be changed to any.

.. zeek:id:: install_dst_net_filter

   :Type: :zeek:type:`function` (snet: :zeek:type:`subnet`, tcp_flags: :zeek:type:`count`, prob: :zeek:type:`double`) : :zeek:type:`bool`

   Installs a filter to drop packets destined to a given subnet with
   a certain probability if none of a given set of TCP flags are set.
   

   :snet: Drop packets to this subnet.
   

   :tcp_flags: If none of these TCP flags are set, drop packets to *snet* with
              probability *prob*.
   

   :prob: The probability [0.0, 1.0] used to drop packets to *snet*.
   

   :returns: True (unconditionally).
   
   .. zeek:see:: Pcap::precompile_pcap_filter
                Pcap::install_pcap_filter
                install_src_addr_filter
                install_src_net_filter
                uninstall_src_addr_filter
                uninstall_src_net_filter
                install_dst_addr_filter
                uninstall_dst_addr_filter
                uninstall_dst_net_filter
                Pcap::error
   
   .. todo:: The return value should be changed to any.

.. zeek:id:: install_src_addr_filter

   :Type: :zeek:type:`function` (ip: :zeek:type:`addr`, tcp_flags: :zeek:type:`count`, prob: :zeek:type:`double`) : :zeek:type:`bool`

   Installs a filter to drop packets from a given IP source address with
   a certain probability if none of a given set of TCP flags are set.
   Note that for IPv6 packets with a Destination options header that has
   the Home Address option, this filters out against that home address.
   

   :ip: The IP address to drop.
   

   :tcp_flags: If none of these TCP flags are set, drop packets from *ip* with
              probability *prob*.
   

   :prob: The probability [0.0, 1.0] used to drop packets from *ip*.
   

   :returns: True (unconditionally).
   
   .. zeek:see:: Pcap::precompile_pcap_filter
                Pcap::install_pcap_filter
                install_src_net_filter
                uninstall_src_addr_filter
                uninstall_src_net_filter
                install_dst_addr_filter
                install_dst_net_filter
                uninstall_dst_addr_filter
                uninstall_dst_net_filter
                Pcap::error
   
   .. todo:: The return value should be changed to any.

.. zeek:id:: install_src_net_filter

   :Type: :zeek:type:`function` (snet: :zeek:type:`subnet`, tcp_flags: :zeek:type:`count`, prob: :zeek:type:`double`) : :zeek:type:`bool`

   Installs a filter to drop packets originating from a given subnet with
   a certain probability if none of a given set of TCP flags are set.
   

   :snet: The subnet to drop packets from.
   

   :tcp_flags: If none of these TCP flags are set, drop packets from *snet* with
              probability *prob*.
   

   :prob: The probability [0.0, 1.0] used to drop packets from *snet*.
   

   :returns: True (unconditionally).
   
   .. zeek:see:: Pcap::precompile_pcap_filter
                Pcap::install_pcap_filter
                install_src_addr_filter
                uninstall_src_addr_filter
                uninstall_src_net_filter
                install_dst_addr_filter
                install_dst_net_filter
                uninstall_dst_addr_filter
                uninstall_dst_net_filter
                Pcap::error
   
   .. todo:: The return value should be changed to any.

.. zeek:id:: int_to_count

   :Type: :zeek:type:`function` (n: :zeek:type:`int`) : :zeek:type:`count`

   Converts a (positive) :zeek:type:`int` to a :zeek:type:`count`.
   

   :n: The :zeek:type:`int` to convert.
   

   :returns: The :zeek:type:`int` *n* as unsigned integer, or 0 if *n* < 0.

.. zeek:id:: interval_to_double

   :Type: :zeek:type:`function` (i: :zeek:type:`interval`) : :zeek:type:`double`

   Converts an :zeek:type:`interval` to a :zeek:type:`double`.
   

   :i: The :zeek:type:`interval` to convert.
   

   :returns: The :zeek:type:`interval` *i* as :zeek:type:`double`.
   
   .. zeek:see:: double_to_interval

.. zeek:id:: is_external_connection

   :Type: :zeek:type:`function` (c: :zeek:type:`connection`) : :zeek:type:`bool`

   Determines whether a connection has been received externally. For example,
   Broccoli or the Time Machine can send packets to Zeek via a mechanism that is
   one step lower than sending events. This function checks whether the packets
   of a connection stem from one of these external *packet sources*.
   

   :c: The connection to test.
   

   :returns: True if *c* has been received externally.

.. zeek:id:: is_icmp_port

   :Type: :zeek:type:`function` (p: :zeek:type:`port`) : :zeek:type:`bool`

   Checks whether a given :zeek:type:`port` has ICMP as transport protocol.
   

   :p: The :zeek:type:`port` to check.
   

   :returns: True iff *p* is an ICMP port.
   
   .. zeek:see:: is_tcp_port is_udp_port

.. zeek:id:: is_local_interface

   :Type: :zeek:type:`function` (ip: :zeek:type:`addr`) : :zeek:type:`bool`

   Checks whether a given IP address belongs to a local interface.
   

   :ip: The IP address to check.
   

   :returns: True if *ip* belongs to a local interface.

.. zeek:id:: is_remote_event

   :Type: :zeek:type:`function` () : :zeek:type:`bool`

   Checks whether the last raised event came from a remote peer.
   

   :returns: True if the last raised event came from a remote peer.

.. zeek:id:: is_tcp_port

   :Type: :zeek:type:`function` (p: :zeek:type:`port`) : :zeek:type:`bool`

   Checks whether a given :zeek:type:`port` has TCP as transport protocol.
   

   :p: The :zeek:type:`port` to check.
   

   :returns: True iff *p* is a TCP port.
   
   .. zeek:see:: is_udp_port is_icmp_port

.. zeek:id:: is_udp_port

   :Type: :zeek:type:`function` (p: :zeek:type:`port`) : :zeek:type:`bool`

   Checks whether a given :zeek:type:`port` has UDP as transport protocol.
   

   :p: The :zeek:type:`port` to check.
   

   :returns: True iff *p* is a UDP port.
   
   .. zeek:see:: is_icmp_port is_tcp_port

.. zeek:id:: is_v4_addr

   :Type: :zeek:type:`function` (a: :zeek:type:`addr`) : :zeek:type:`bool`

   Returns whether an address is IPv4 or not.
   

   :a: the address to check.
   

   :returns: true if *a* is an IPv4 address, else false.

.. zeek:id:: is_v4_subnet

   :Type: :zeek:type:`function` (s: :zeek:type:`subnet`) : :zeek:type:`bool`

   Returns whether a subnet specification is IPv4 or not.
   

   :s: the subnet to check.
   

   :returns: true if *s* is an IPv4 subnet, else false.

.. zeek:id:: is_v6_addr

   :Type: :zeek:type:`function` (a: :zeek:type:`addr`) : :zeek:type:`bool`

   Returns whether an address is IPv6 or not.
   

   :a: the address to check.
   

   :returns: true if *a* is an IPv6 address, else false.

.. zeek:id:: is_v6_subnet

   :Type: :zeek:type:`function` (s: :zeek:type:`subnet`) : :zeek:type:`bool`

   Returns whether a subnet specification is IPv6 or not.
   

   :s: the subnet to check.
   

   :returns: true if *s* is an IPv6 subnet, else false.

.. zeek:id:: is_valid_ip

   :Type: :zeek:type:`function` (ip: :zeek:type:`string`) : :zeek:type:`bool`

   Checks if a string is a valid IPv4 or IPv6 address.
   

   :ip: the string to check for valid IP formatting.
   

   :returns: T if the string is a valid IPv4 or IPv6 address format.

.. zeek:id:: ln

   :Type: :zeek:type:`function` (d: :zeek:type:`double`) : :zeek:type:`double`

   Computes the natural logarithm of a number.
   

   :d: The argument to the logarithm.
   

   :returns: The natural logarithm of *d*.
   
   .. zeek:see:: exp floor sqrt log10

.. zeek:id:: log10

   :Type: :zeek:type:`function` (d: :zeek:type:`double`) : :zeek:type:`double`

   Computes the common logarithm of a number.
   

   :d: The argument to the logarithm.
   

   :returns: The common logarithm of *d*.
   
   .. zeek:see:: exp floor sqrt ln

.. zeek:id:: lookup_ID

   :Type: :zeek:type:`function` (id: :zeek:type:`string`) : :zeek:type:`any`

   Returns the value of a global identifier.
   

   :id: The global identifier.
   

   :returns: The value of *id*. If *id* does not describe a valid identifier,
            the string ``"<unknown id>"`` or ``"<no ID value>"`` is returned.

.. zeek:id:: lookup_addr

   :Type: :zeek:type:`function` (host: :zeek:type:`addr`) : :zeek:type:`string`

   Issues an asynchronous reverse DNS lookup and delays the function result.
   This function can therefore only be called inside a ``when`` condition,
   e.g., ``when ( local host = lookup_addr(10.0.0.1) ) { f(host); }``.
   

   :host: The IP address to lookup.
   

   :returns: The DNS name of *host*.
   
   .. zeek:see:: lookup_hostname

.. zeek:id:: lookup_asn

   :Type: :zeek:type:`function` (a: :zeek:type:`addr`) : :zeek:type:`count`

   Performs an ASN lookup of an IP address.
   Requires Zeek to be built with ``libmaxminddb``.
   

   :a: The IP address to lookup.
   

   :returns: The number of the ASN that contains *a*.
   
   .. zeek:see:: lookup_location

.. zeek:id:: lookup_connection

   :Type: :zeek:type:`function` (cid: :zeek:type:`conn_id`) : :zeek:type:`connection`

   Returns the :zeek:type:`connection` record for a given connection identifier.
   

   :cid: The connection ID.
   

   :returns: The :zeek:type:`connection` record for *cid*. If *cid* does not point
            to an existing connection, the function generates a run-time error
            and returns a dummy value.
   
   .. zeek:see:: connection_exists

.. zeek:id:: lookup_hostname

   :Type: :zeek:type:`function` (host: :zeek:type:`string`) : :zeek:type:`addr_set`

   Issues an asynchronous DNS lookup and delays the function result.
   This function can therefore only be called inside a ``when`` condition,
   e.g., ``when ( local h = lookup_hostname("www.zeek.org") ) { f(h); }``.
   

   :host: The hostname to lookup.
   

   :returns: A set of DNS A and AAAA records associated with *host*.
   
   .. zeek:see:: lookup_addr

.. zeek:id:: lookup_hostname_txt

   :Type: :zeek:type:`function` (host: :zeek:type:`string`) : :zeek:type:`string`

   Issues an asynchronous TEXT DNS lookup and delays the function result.
   This function can therefore only be called inside a ``when`` condition,
   e.g., ``when ( local h = lookup_hostname_txt("www.zeek.org") ) { f(h); }``.
   

   :host: The hostname to lookup.
   

   :returns: The DNS TXT record associated with *host*.
   
   .. zeek:see:: lookup_hostname

.. zeek:id:: lookup_location

   :Type: :zeek:type:`function` (a: :zeek:type:`addr`) : :zeek:type:`geo_location`

   Performs a geo-lookup of an IP address.
   Requires Zeek to be built with ``libmaxminddb``.
   

   :a: The IP address to lookup.
   

   :returns: A record with country, region, city, latitude, and longitude.
   
   .. zeek:see:: lookup_asn

.. zeek:id:: mask_addr

   :Type: :zeek:type:`function` (a: :zeek:type:`addr`, top_bits_to_keep: :zeek:type:`count`) : :zeek:type:`subnet`

   Masks an address down to the number of given upper bits. For example,
   ``mask_addr(1.2.3.4, 18)`` returns ``1.2.0.0``.
   

   :a: The address to mask.
   

   :top_bits_to_keep: The number of top bits to keep in *a*; must be greater
                     than 0 and less than 33 for IPv4, or 129 for IPv6.
   

   :returns: The address *a* masked down to *top_bits_to_keep* bits.
   
   .. zeek:see:: remask_addr

.. zeek:id:: match_signatures

   :Type: :zeek:type:`function` (c: :zeek:type:`connection`, pattern_type: :zeek:type:`int`, s: :zeek:type:`string`, bol: :zeek:type:`bool`, eol: :zeek:type:`bool`, from_orig: :zeek:type:`bool`, clear: :zeek:type:`bool`) : :zeek:type:`bool`

   Manually triggers the signature engine for a given connection.
   This is an internal function.

.. zeek:id:: matching_subnets

   :Type: :zeek:type:`function` (search: :zeek:type:`subnet`, t: :zeek:type:`any`) : :zeek:type:`subnet_vec`

   Gets all subnets that contain a given subnet from a set/table[subnet].
   

   :search: the subnet to search for.
   

   :t: the set[subnet] or table[subnet].
   

   :returns: All the keys of the set or table that cover the subnet searched for.

.. zeek:id:: md5_hash

   :Type: :zeek:type:`function` (...) : :zeek:type:`string`

   Computes the MD5 hash value of the provided list of arguments.
   

   :returns: The MD5 hash value of the concatenated arguments.
   
   .. zeek:see:: md5_hmac md5_hash_init md5_hash_update md5_hash_finish
      sha1_hash sha1_hash_init sha1_hash_update sha1_hash_finish
      sha256_hash sha256_hash_init sha256_hash_update sha256_hash_finish
   
   .. note::
   
        This function performs a one-shot computation of its arguments.
        For incremental hash computation, see :zeek:id:`md5_hash_init` and
        friends.

.. zeek:id:: md5_hash_finish

   :Type: :zeek:type:`function` (handle: :zeek:type:`opaque` of md5) : :zeek:type:`string`

   Returns the final MD5 digest of an incremental hash computation.
   

   :handle: The opaque handle associated with this hash computation.
   

   :returns: The hash value associated with the computation of *handle*.
   
   .. zeek:see:: md5_hmac md5_hash md5_hash_init md5_hash_update
      sha1_hash sha1_hash_init sha1_hash_update sha1_hash_finish
      sha256_hash sha256_hash_init sha256_hash_update sha256_hash_finish

.. zeek:id:: md5_hash_init

   :Type: :zeek:type:`function` () : :zeek:type:`opaque` of md5

   Constructs an MD5 handle to enable incremental hash computation. You can
   feed data to the returned opaque value with :zeek:id:`md5_hash_update` and
   eventually need to call :zeek:id:`md5_hash_finish` to finish the computation
   and get the hash digest.
   
   For example, when computing incremental MD5 values of transferred files in
   multiple concurrent HTTP connections, one keeps an optional handle in the
   HTTP session record. Then, one would call
   ``c$http$md5_handle = md5_hash_init()`` once before invoking
   ``md5_hash_update(c$http$md5_handle, some_more_data)`` in the
   :zeek:id:`http_entity_data` event handler. When all data has arrived, a call
   to :zeek:id:`md5_hash_finish` returns the final hash value.
   

   :returns: The opaque handle associated with this hash computation.
   
   .. zeek:see:: md5_hmac md5_hash md5_hash_update md5_hash_finish
      sha1_hash sha1_hash_init sha1_hash_update sha1_hash_finish
      sha256_hash sha256_hash_init sha256_hash_update sha256_hash_finish

.. zeek:id:: md5_hash_update

   :Type: :zeek:type:`function` (handle: :zeek:type:`opaque` of md5, data: :zeek:type:`string`) : :zeek:type:`bool`

   Updates the MD5 value associated with a given index. It is required to
   call :zeek:id:`md5_hash_init` once before calling this
   function.
   

   :handle: The opaque handle associated with this hash computation.
   

   :data: The data to add to the hash computation.
   

   :returns: True on success.
   
   .. zeek:see:: md5_hmac md5_hash md5_hash_init md5_hash_finish
      sha1_hash sha1_hash_init sha1_hash_update sha1_hash_finish
      sha256_hash sha256_hash_init sha256_hash_update sha256_hash_finish

.. zeek:id:: md5_hmac

   :Type: :zeek:type:`function` (...) : :zeek:type:`string`

   Computes an HMAC-MD5 hash value of the provided list of arguments. The HMAC
   secret key is generated from available entropy when Zeek starts up, or it can
   be specified for repeatability using the ``-K`` command line flag.
   

   :returns: The HMAC-MD5 hash value of the concatenated arguments.
   
   .. zeek:see:: md5_hash md5_hash_init md5_hash_update md5_hash_finish
      sha1_hash sha1_hash_init sha1_hash_update sha1_hash_finish
      sha256_hash sha256_hash_init sha256_hash_update sha256_hash_finish

.. zeek:id:: mkdir

   :Type: :zeek:type:`function` (f: :zeek:type:`string`) : :zeek:type:`bool`

   Creates a new directory.
   

   :f: The directory name.
   

   :returns: True if the operation succeeds or if *f* already exists,
            and false if the file creation fails.
   
   .. zeek:see:: active_file open_for_append close write_file
                get_file_name set_buf flush_all enable_raw_output
                rmdir unlink rename

.. zeek:id:: mmdb_open_asn_db

   :Type: :zeek:type:`function` (f: :zeek:type:`string`) : :zeek:type:`bool`

   Initializes MMDB for later use of lookup_asn.
   Requires Zeek to be built with ``libmaxminddb``.
   

   :f: The filename of the MaxMind ASN DB.
   

   :returns: A boolean indicating whether the db was successfully opened.
   
   .. zeek:see:: lookup_asn

.. zeek:id:: mmdb_open_location_db

   :Type: :zeek:type:`function` (f: :zeek:type:`string`) : :zeek:type:`bool`

   Initializes MMDB for later use of lookup_location.
   Requires Zeek to be built with ``libmaxminddb``.
   

   :f: The filename of the MaxMind City or Country DB.
   

   :returns: A boolean indicating whether the db was successfully opened.
   
   .. zeek:see:: lookup_asn

.. zeek:id:: network_time

   :Type: :zeek:type:`function` () : :zeek:type:`time`

   Returns the timestamp of the last packet processed. This function returns
   the timestamp of the most recently read packet, whether read from a
   live network interface or from a save file.
   

   :returns: The timestamp of the packet processed.
   
   .. zeek:see:: current_time

.. zeek:id:: open

   :Type: :zeek:type:`function` (f: :zeek:type:`string`) : :zeek:type:`file`

   Opens a file for writing. If a file with the same name already exists, this
   function overwrites it (as opposed to :zeek:id:`open_for_append`).
   

   :f: The path to the file.
   

   :returns: A :zeek:type:`file` handle for subsequent operations.
   
   .. zeek:see:: active_file open_for_append close write_file
                get_file_name set_buf flush_all mkdir enable_raw_output
                rmdir unlink rename

.. zeek:id:: open_for_append

   :Type: :zeek:type:`function` (f: :zeek:type:`string`) : :zeek:type:`file`

   Opens a file for writing or appending. If a file with the same name already
   exists, this function appends to it (as opposed to :zeek:id:`open`).
   

   :f: The path to the file.
   

   :returns: A :zeek:type:`file` handle for subsequent operations.
   
   .. zeek:see:: active_file open close write_file
                get_file_name set_buf flush_all mkdir enable_raw_output
                rmdir unlink rename

.. zeek:id:: order

   :Type: :zeek:type:`function` (...) : :zeek:type:`index_vec`

   Returns the order of the elements in a vector according to some
   comparison function. See :zeek:id:`sort` for details about the comparison
   function.
   

   :v: The vector whose order to compute.
   

   :returns: A ``vector of count`` with the indices of the ordered elements.
            For example, the elements of *v* in order are (assuming ``o``
            is the vector returned by ``order``):  v[o[0]], v[o[1]], etc.
   
   .. zeek:see:: sort

.. zeek:id:: paraglob_equals

   :Type: :zeek:type:`function` (p_one: :zeek:type:`opaque` of paraglob, p_two: :zeek:type:`opaque` of paraglob) : :zeek:type:`bool`

   Compares two paraglobs for equality.
   

   :p_one: A compiled paraglob.
   

   :p_two: A compiled paraglob.
   

   :returns: True if both paraglobs contain the same patterns, false otherwise.
   
   ## .. zeek:see::paraglob_add paraglob_match paraglob_init

.. zeek:id:: paraglob_init

   :Type: :zeek:type:`function` (v: :zeek:type:`any`) : :zeek:type:`opaque` of paraglob

   Initializes and returns a new paraglob.
   

   :v: Vector of patterns to initialize the paraglob with.
   

   :returns: A new, compiled, paraglob with the patterns in *v*
   
   .. zeek:see::paraglob_match paraglob_equals paraglob_add

.. zeek:id:: paraglob_match

   :Type: :zeek:type:`function` (handle: :zeek:type:`opaque` of paraglob, match: :zeek:type:`string`) : :zeek:type:`string_vec`

   Gets all the patterns inside the handle associated with an input string.
   

   :handle: A compiled paraglob.
   

   :match: string to match against the paraglob.
   

   :returns: A vector of strings matching the input string.
   
   ## .. zeek:see::paraglob_add paraglob_equals paraglob_init

.. zeek:id:: piped_exec

   :Type: :zeek:type:`function` (program: :zeek:type:`string`, to_write: :zeek:type:`string`) : :zeek:type:`bool`

   Opens a program with ``popen`` and writes a given string to the returned
   stream to send it to the opened process's stdin.
   

   :program: The program to execute.
   

   :to_write: Data to pipe to the opened program's process via ``stdin``.
   

   :returns: True on success.
   
   .. zeek:see:: system system_env

.. zeek:id:: port_to_count

   :Type: :zeek:type:`function` (p: :zeek:type:`port`) : :zeek:type:`count`

   Converts a :zeek:type:`port` to a :zeek:type:`count`.
   

   :p: The :zeek:type:`port` to convert.
   

   :returns: The :zeek:type:`port` *p* as :zeek:type:`count`.
   
   .. zeek:see:: count_to_port

.. zeek:id:: preserve_prefix

   :Type: :zeek:type:`function` (a: :zeek:type:`addr`, width: :zeek:type:`count`) : :zeek:type:`any`

   Preserves the prefix of an IP address in anonymization.
   

   :a: The address to preserve.
   

   :width: The number of bits from the top that should remain intact.
   
   .. zeek:see:: preserve_subnet anonymize_addr
   
   .. todo:: Currently dysfunctional.

.. zeek:id:: preserve_subnet

   :Type: :zeek:type:`function` (a: :zeek:type:`subnet`) : :zeek:type:`any`

   Preserves the prefix of a subnet in anonymization.
   

   :a: The subnet to preserve.
   
   .. zeek:see:: preserve_prefix anonymize_addr
   
   .. todo:: Currently dysfunctional.

.. zeek:id:: ptr_name_to_addr

   :Type: :zeek:type:`function` (s: :zeek:type:`string`) : :zeek:type:`addr`

   Converts a reverse pointer name to an address. For example,
   ``1.0.168.192.in-addr.arpa`` to ``192.168.0.1``.
   

   :s: The string with the reverse pointer name.
   

   :returns: The IP address corresponding to *s*.
   
   .. zeek:see:: addr_to_ptr_name to_addr

.. zeek:id:: rand

   :Type: :zeek:type:`function` (max: :zeek:type:`count`) : :zeek:type:`count`

   Generates a random number.
   

   :max: The maximum value of the random number.
   

   :returns: a random positive integer in the interval *[0, max)*.
   
   .. zeek:see:: srand
   
   .. note::
   
        This function is a wrapper about the function ``random``
        provided by the OS.

.. zeek:id:: raw_bytes_to_v4_addr

   :Type: :zeek:type:`function` (b: :zeek:type:`string`) : :zeek:type:`addr`

   Converts a :zeek:type:`string` of bytes into an IPv4 address. In particular,
   this function interprets the first 4 bytes of the string as an IPv4 address
   in network order.
   

   :b: The raw bytes (:zeek:type:`string`) to convert.
   

   :returns: The byte :zeek:type:`string` *b* as :zeek:type:`addr`.
   
   .. zeek:see:: raw_bytes_to_v4_addr to_addr to_subnet

.. zeek:id:: reading_live_traffic

   :Type: :zeek:type:`function` () : :zeek:type:`bool`

   Checks whether Zeek reads traffic from one or more network interfaces (as
   opposed to from a network trace in a file). Note that this function returns
   true even after Zeek has stopped reading network traffic, for example due to
   receiving a termination signal.
   

   :returns: True if reading traffic from a network interface.
   
   .. zeek:see:: reading_traces

.. zeek:id:: reading_traces

   :Type: :zeek:type:`function` () : :zeek:type:`bool`

   Checks whether Zeek reads traffic from a trace file (as opposed to from a
   network interface).
   

   :returns: True if reading traffic from a network trace.
   
   .. zeek:see:: reading_live_traffic

.. zeek:id:: record_fields

   :Type: :zeek:type:`function` (rec: :zeek:type:`any`) : :zeek:type:`record_field_table`

   Generates metadata about a record's fields. The returned information
   includes the field name, whether it is logged, its value (if it has one),
   and its default value (if specified).
   

   :rec: The record value or type to inspect.
   

   :returns: A table that describes the fields of a record.

.. zeek:id:: record_type_to_vector

   :Type: :zeek:type:`function` (rt: :zeek:type:`string`) : :zeek:type:`string_vec`

   Converts a record type name to a vector of strings, where each element is
   the name of a record field. Nested records are flattened.
   

   :rt: The name of the record type.
   

   :returns: A string vector with the field names of *rt*.

.. zeek:id:: remask_addr

   :Type: :zeek:type:`function` (a1: :zeek:type:`addr`, a2: :zeek:type:`addr`, top_bits_from_a1: :zeek:type:`count`) : :zeek:type:`addr`

   Takes some top bits (such as a subnet address) from one address and the other
   bits (intra-subnet part) from a second address and merges them to get a new
   address. This is useful for anonymizing at subnet level while preserving
   serial scans.
   

   :a1: The address to mask with *top_bits_from_a1*.
   

   :a2: The address to take the remaining bits from.
   

   :top_bits_from_a1: The number of top bits to keep in *a1*; must be greater
                     than 0 and less than 129.  This value is always interpreted
                     relative to the IPv6 bit width (v4-mapped addresses start
                     at bit number 96).
   

   :returns: The address *a* masked down to *top_bits_to_keep* bits.
   
   .. zeek:see:: mask_addr

.. zeek:id:: rename

   :Type: :zeek:type:`function` (src_f: :zeek:type:`string`, dst_f: :zeek:type:`string`) : :zeek:type:`bool`

   Renames a file from src_f to dst_f.
   

   :src_f: the name of the file to rename.
   

   :dest_f: the name of the file after the rename operation.
   

   :returns: True if the rename succeeds and false otherwise.
   
   .. zeek:see:: active_file open_for_append close write_file
                get_file_name set_buf flush_all enable_raw_output
                mkdir rmdir unlink

.. zeek:id:: resize

   :Type: :zeek:type:`function` (aggr: :zeek:type:`any`, newsize: :zeek:type:`count`) : :zeek:type:`count`

   Resizes a vector.
   

   :aggr: The vector instance.
   

   :newsize: The new size of *aggr*.
   

   :returns: The old size of *aggr*, or 0 if *aggr* is not a :zeek:type:`vector`.

.. zeek:id:: rmdir

   :Type: :zeek:type:`function` (d: :zeek:type:`string`) : :zeek:type:`bool`

   Removes a directory.
   

   :d: The directory name.
   

   :returns: True if the operation succeeds, and false if the
            directory delete operation fails.
   
   .. zeek:see:: active_file open_for_append close write_file
                get_file_name set_buf flush_all enable_raw_output
                mkdir unlink rename

.. zeek:id:: rotate_file

   :Type: :zeek:type:`function` (f: :zeek:type:`file`) : :zeek:type:`rotate_info`

   Rotates a file.
   

   :f: An open file handle.
   

   :returns: Rotation statistics which include the original file name, the name
            after the rotation, and the time when *f* was opened/closed.
   
   .. zeek:see:: rotate_file_by_name calc_next_rotate

.. zeek:id:: rotate_file_by_name

   :Type: :zeek:type:`function` (f: :zeek:type:`string`) : :zeek:type:`rotate_info`

   Rotates a file identified by its name.
   

   :f: The name of the file to rotate
   

   :returns: Rotation statistics which include the original file name, the name
            after the rotation, and the time when *f* was opened/closed.
   
   .. zeek:see:: rotate_file calc_next_rotate

.. zeek:id:: routing0_data_to_addrs

   :Type: :zeek:type:`function` (s: :zeek:type:`string`) : :zeek:type:`addr_vec`

   Converts the *data* field of :zeek:type:`ip6_routing` records that have
   *rtype* of 0 into a vector of addresses.
   

   :s: The *data* field of an :zeek:type:`ip6_routing` record that has
      an *rtype* of 0.
   

   :returns: The vector of addresses contained in the routing header data.

.. zeek:id:: same_object

   :Type: :zeek:type:`function` (o1: :zeek:type:`any`, o2: :zeek:type:`any`) : :zeek:type:`bool`

   Checks whether two objects reference the same internal object. This function
   uses equality comparison of C++ raw pointer values to determine if the two
   objects are the same.
   

   :o1: The first object.
   

   :o2: The second object.
   

   :returns: True if *o1* and *o2* are equal.

.. zeek:id:: set_buf

   :Type: :zeek:type:`function` (f: :zeek:type:`file`, buffered: :zeek:type:`bool`) : :zeek:type:`any`

   Alters the buffering behavior of a file.
   

   :f: A :zeek:type:`file` handle to an open file.
   

   :buffered: When true, *f* is fully buffered, i.e., bytes are saved in a
             buffer until the block size has been reached. When
             false, *f* is line buffered, i.e., bytes are saved up until a
             newline occurs.
   
   .. zeek:see:: active_file open open_for_append close
                get_file_name write_file flush_all mkdir enable_raw_output
                rmdir unlink rename

.. zeek:id:: set_inactivity_timeout

   :Type: :zeek:type:`function` (cid: :zeek:type:`conn_id`, t: :zeek:type:`interval`) : :zeek:type:`interval`

   Sets an individual inactivity timeout for a connection and thus
   overrides the global inactivity timeout.
   

   :cid: The connection ID.
   

   :t: The new inactivity timeout for the connection identified by *cid*.
   

   :returns: The previous timeout interval.

.. zeek:id:: set_record_packets

   :Type: :zeek:type:`function` (cid: :zeek:type:`conn_id`, do_record: :zeek:type:`bool`) : :zeek:type:`bool`

   Controls whether packet contents belonging to a connection should be
   recorded (when ``-w`` option is provided on the command line).
   

   :cid: The connection identifier.
   

   :do_record: True to enable packet contents, and false to disable for the
              connection identified by *cid*.
   

   :returns: False if *cid* does not point to an active connection, and true
            otherwise.
   
   .. zeek:see:: skip_further_processing
   
   .. note::
   
       This is independent of whether Zeek processes the packets of this
       connection, which is controlled separately by
       :zeek:id:`skip_further_processing`.
   
   .. zeek:see:: get_contents_file set_contents_file

.. zeek:id:: setenv

   :Type: :zeek:type:`function` (var: :zeek:type:`string`, val: :zeek:type:`string`) : :zeek:type:`bool`

   Sets a system environment variable.
   

   :var: The name of the variable.
   

   :val: The (new) value of the variable *var*.
   

   :returns: True on success.
   
   .. zeek:see:: getenv

.. zeek:id:: sha1_hash

   :Type: :zeek:type:`function` (...) : :zeek:type:`string`

   Computes the SHA1 hash value of the provided list of arguments.
   

   :returns: The SHA1 hash value of the concatenated arguments.
   
   .. zeek:see:: md5_hash md5_hmac md5_hash_init md5_hash_update md5_hash_finish
      sha1_hash_init sha1_hash_update sha1_hash_finish
      sha256_hash sha256_hash_init sha256_hash_update sha256_hash_finish
   
   .. note::
   
        This function performs a one-shot computation of its arguments.
        For incremental hash computation, see :zeek:id:`sha1_hash_init` and
        friends.

.. zeek:id:: sha1_hash_finish

   :Type: :zeek:type:`function` (handle: :zeek:type:`opaque` of sha1) : :zeek:type:`string`

   Returns the final SHA1 digest of an incremental hash computation.
   

   :handle: The opaque handle associated with this hash computation.
   

   :returns: The hash value associated with the computation of *handle*.
   
   .. zeek:see:: md5_hmac md5_hash md5_hash_init md5_hash_update md5_hash_finish
      sha1_hash sha1_hash_init sha1_hash_update
      sha256_hash sha256_hash_init sha256_hash_update sha256_hash_finish

.. zeek:id:: sha1_hash_init

   :Type: :zeek:type:`function` () : :zeek:type:`opaque` of sha1

   Constructs an SHA1 handle to enable incremental hash computation. You can
   feed data to the returned opaque value with :zeek:id:`sha1_hash_update` and
   finally need to call :zeek:id:`sha1_hash_finish` to finish the computation
   and get the hash digest.
   
   For example, when computing incremental SHA1 values of transferred files in
   multiple concurrent HTTP connections, one keeps an optional handle in the
   HTTP session record. Then, one would call
   ``c$http$sha1_handle = sha1_hash_init()`` once before invoking
   ``sha1_hash_update(c$http$sha1_handle, some_more_data)`` in the
   :zeek:id:`http_entity_data` event handler. When all data has arrived, a call
   to :zeek:id:`sha1_hash_finish` returns the final hash value.
   

   :returns: The opaque handle associated with this hash computation.
   
   .. zeek:see:: md5_hmac md5_hash md5_hash_init md5_hash_update md5_hash_finish
      sha1_hash sha1_hash_update sha1_hash_finish
      sha256_hash sha256_hash_init sha256_hash_update sha256_hash_finish

.. zeek:id:: sha1_hash_update

   :Type: :zeek:type:`function` (handle: :zeek:type:`opaque` of sha1, data: :zeek:type:`string`) : :zeek:type:`bool`

   Updates the SHA1 value associated with a given index. It is required to
   call :zeek:id:`sha1_hash_init` once before calling this
   function.
   

   :handle: The opaque handle associated with this hash computation.
   

   :data: The data to add to the hash computation.
   

   :returns: True on success.
   
   .. zeek:see:: md5_hmac md5_hash md5_hash_init md5_hash_update md5_hash_finish
      sha1_hash sha1_hash_init sha1_hash_finish
      sha256_hash sha256_hash_init sha256_hash_update sha256_hash_finish

.. zeek:id:: sha256_hash

   :Type: :zeek:type:`function` (...) : :zeek:type:`string`

   Computes the SHA256 hash value of the provided list of arguments.
   

   :returns: The SHA256 hash value of the concatenated arguments.
   
   .. zeek:see:: md5_hash md5_hmac md5_hash_init md5_hash_update md5_hash_finish
      sha1_hash sha1_hash_init sha1_hash_update sha1_hash_finish
      sha256_hash_init sha256_hash_update sha256_hash_finish
   
   .. note::
   
        This function performs a one-shot computation of its arguments.
        For incremental hash computation, see :zeek:id:`sha256_hash_init` and
        friends.

.. zeek:id:: sha256_hash_finish

   :Type: :zeek:type:`function` (handle: :zeek:type:`opaque` of sha256) : :zeek:type:`string`

   Returns the final SHA256 digest of an incremental hash computation.
   

   :handle: The opaque handle associated with this hash computation.
   

   :returns: The hash value associated with the computation of *handle*.
   
   .. zeek:see:: md5_hmac md5_hash md5_hash_init md5_hash_update md5_hash_finish
      sha1_hash sha1_hash_init sha1_hash_update sha1_hash_finish
      sha256_hash sha256_hash_init sha256_hash_update

.. zeek:id:: sha256_hash_init

   :Type: :zeek:type:`function` () : :zeek:type:`opaque` of sha256

   Constructs an SHA256 handle to enable incremental hash computation. You can
   feed data to the returned opaque value with :zeek:id:`sha256_hash_update` and
   finally need to call :zeek:id:`sha256_hash_finish` to finish the computation
   and get the hash digest.
   
   For example, when computing incremental SHA256 values of transferred files in
   multiple concurrent HTTP connections, one keeps an optional handle in the
   HTTP session record. Then, one would call
   ``c$http$sha256_handle = sha256_hash_init()`` once before invoking
   ``sha256_hash_update(c$http$sha256_handle, some_more_data)`` in the
   :zeek:id:`http_entity_data` event handler. When all data has arrived, a call
   to :zeek:id:`sha256_hash_finish` returns the final hash value.
   

   :returns: The opaque handle associated with this hash computation.
   
   .. zeek:see:: md5_hmac md5_hash md5_hash_init md5_hash_update md5_hash_finish
      sha1_hash sha1_hash_init sha1_hash_update sha1_hash_finish
      sha256_hash sha256_hash_update sha256_hash_finish

.. zeek:id:: sha256_hash_update

   :Type: :zeek:type:`function` (handle: :zeek:type:`opaque` of sha256, data: :zeek:type:`string`) : :zeek:type:`bool`

   Updates the SHA256 value associated with a given index. It is required to
   call :zeek:id:`sha256_hash_init` once before calling this
   function.
   

   :handle: The opaque handle associated with this hash computation.
   

   :data: The data to add to the hash computation.
   

   :returns: True on success.
   
   .. zeek:see:: md5_hmac md5_hash md5_hash_init md5_hash_update md5_hash_finish
      sha1_hash sha1_hash_init sha1_hash_update sha1_hash_finish
      sha256_hash sha256_hash_init sha256_hash_finish

.. zeek:id:: skip_further_processing

   :Type: :zeek:type:`function` (cid: :zeek:type:`conn_id`) : :zeek:type:`bool`

   Informs Zeek that it should skip any further processing of the contents of
   a given connection. In particular, Zeek will refrain from reassembling the
   TCP byte stream and from generating events relating to any analyzers that
   have been processing the connection.
   

   :cid: The connection ID.
   

   :returns: False if *cid* does not point to an active connection, and true
            otherwise.
   
   .. note::
   
       Zeek will still generate connection-oriented events such as
       :zeek:id:`connection_finished`.

.. zeek:id:: sort

   :Type: :zeek:type:`function` (...) : :zeek:type:`any`

   Sorts a vector in place. The second argument is a comparison function that
   takes two arguments: if the vector type is ``vector of T``, then the
   comparison function must be ``function(a: T, b: T): int``, which returns
   a value less than zero if ``a < b`` for some type-specific notion of the
   less-than operator.  The comparison function is optional if the type
   is an integral type (int, count, etc.).
   

   :v: The vector instance to sort.
   

   :returns: The vector, sorted from minimum to maximum value. If the vector
            could not be sorted, then the original vector is returned instead.
   
   .. zeek:see:: order

.. zeek:id:: sqrt

   :Type: :zeek:type:`function` (x: :zeek:type:`double`) : :zeek:type:`double`

   Computes the square root of a :zeek:type:`double`.
   

   :x: The number to compute the square root of.
   

   :returns: The square root of *x*.
   
   .. zeek:see:: floor exp ln log10

.. zeek:id:: srand

   :Type: :zeek:type:`function` (seed: :zeek:type:`count`) : :zeek:type:`any`

   Sets the seed for subsequent :zeek:id:`rand` calls.
   

   :seed: The seed for the PRNG.
   
   .. zeek:see:: rand
   
   .. note::
   
        This function is a wrapper about the function ``srandom``
        provided by the OS.

.. zeek:id:: strftime

   :Type: :zeek:type:`function` (fmt: :zeek:type:`string`, d: :zeek:type:`time`) : :zeek:type:`string`

   Formats a given time value according to a format string.
   

   :fmt: The format string. See ``man strftime`` for the syntax.
   

   :d: The time value.
   

   :returns: The time *d* formatted according to *fmt*.

.. zeek:id:: string_to_pattern

   :Type: :zeek:type:`function` (s: :zeek:type:`string`, convert: :zeek:type:`bool`) : :zeek:type:`pattern`

   Converts a :zeek:type:`string` into a :zeek:type:`pattern`.
   

   :s: The string to convert.
   

   :convert: If true, *s* is first passed through the function
            :zeek:id:`convert_for_pattern` to escape special characters of
            patterns.
   

   :returns: *s* as :zeek:type:`pattern`.
   
   .. zeek:see:: convert_for_pattern
   
   .. note::
   
        This function must be called at Zeek startup time, e.g., in the event
        :zeek:id:`zeek_init`.

.. zeek:id:: strptime

   :Type: :zeek:type:`function` (fmt: :zeek:type:`string`, d: :zeek:type:`string`) : :zeek:type:`time`

   Parse a textual representation of a date/time value into a ``time`` type value.
   

   :fmt: The format string used to parse the following *d* argument. See ``man strftime``
        for the syntax.
   

   :d: The string representing the time.
   

   :returns: The time value calculated from parsing *d* with *fmt*.

.. zeek:id:: subnet_to_addr

   :Type: :zeek:type:`function` (sn: :zeek:type:`subnet`) : :zeek:type:`addr`

   Converts a :zeek:type:`subnet` to an :zeek:type:`addr` by
   extracting the prefix.
   

   :sn: The subnet to convert.
   

   :returns: The subnet as an :zeek:type:`addr`.
   
   .. zeek:see:: to_subnet

.. zeek:id:: subnet_width

   :Type: :zeek:type:`function` (sn: :zeek:type:`subnet`) : :zeek:type:`count`

   Returns the width of a :zeek:type:`subnet`.
   

   :sn: The subnet.
   

   :returns: The width of the subnet.
   
   .. zeek:see:: to_subnet

.. zeek:id:: suspend_processing

   :Type: :zeek:type:`function` () : :zeek:type:`any`

   Stops Zeek's packet processing. This function is used to synchronize
   distributed trace processing with communication enabled
   (*pseudo-realtime* mode).
   
   .. zeek:see:: continue_processing

.. zeek:id:: syslog

   :Type: :zeek:type:`function` (s: :zeek:type:`string`) : :zeek:type:`any`

   Send a string to syslog.
   

   :s: The string to log via syslog

.. zeek:id:: system

   :Type: :zeek:type:`function` (str: :zeek:type:`string`) : :zeek:type:`int`

   Invokes a command via the ``system`` function of the OS.
   The command runs in the background with ``stdout`` redirecting to
   ``stderr``. Here is a usage example:
   ``system(fmt("rm %s", safe_shell_quote(sniffed_data)));``
   

   :str: The command to execute.
   

   :returns: The return value from the OS ``system`` function.
   
   .. zeek:see:: system_env safe_shell_quote piped_exec
   
   .. note::
   
        Note that this corresponds to the status of backgrounding the
        given command, not to the exit status of the command itself. A
        value of 127 corresponds to a failure to execute ``sh``, and -1
        to an internal system failure.

.. zeek:id:: system_env

   :Type: :zeek:type:`function` (str: :zeek:type:`string`, env: :zeek:type:`table_string_of_string`) : :zeek:type:`int`

   Invokes a command via the ``system`` function of the OS with a prepared
   environment. The function is essentially the same as :zeek:id:`system`,
   but changes the environment before invoking the command.
   

   :str: The command to execute.
   

   :env: A :zeek:type:`table` with the environment variables in the form
        of key-value pairs. Each specified environment variable name
        will be automatically prepended with ``ZEEK_ARG_``.
   

   :returns: The return value from the OS ``system`` function.
   
   .. zeek:see:: system safe_shell_quote piped_exec

.. zeek:id:: terminate

   :Type: :zeek:type:`function` () : :zeek:type:`bool`

   Gracefully shut down Zeek by terminating outstanding processing.
   

   :returns: True after successful termination and false when Zeek is still in
            the process of shutting down.
   
   .. zeek:see:: exit zeek_is_terminating

.. zeek:id:: time_to_double

   :Type: :zeek:type:`function` (t: :zeek:type:`time`) : :zeek:type:`double`

   Converts a :zeek:type:`time` value to a :zeek:type:`double`.
   

   :t: The :zeek:type:`time` to convert.
   

   :returns: The :zeek:type:`time` value *t* as :zeek:type:`double`.
   
   .. zeek:see:: double_to_time

.. zeek:id:: to_addr

   :Type: :zeek:type:`function` (ip: :zeek:type:`string`) : :zeek:type:`addr`

   Converts a :zeek:type:`string` to an :zeek:type:`addr`.
   

   :ip: The :zeek:type:`string` to convert.
   

   :returns: The :zeek:type:`string` *ip* as :zeek:type:`addr`, or the unspecified
            address ``::`` if the input string does not parse correctly.
   
   .. zeek:see:: to_count to_int to_port count_to_v4_addr raw_bytes_to_v4_addr
      to_subnet

.. zeek:id:: to_count

   :Type: :zeek:type:`function` (str: :zeek:type:`string`) : :zeek:type:`count`

   Converts a :zeek:type:`string` to a :zeek:type:`count`.
   

   :str: The :zeek:type:`string` to convert.
   

   :returns: The :zeek:type:`string` *str* as unsigned integer, or 0 if *str* has
            an invalid format.
   
   .. zeek:see:: to_addr to_int to_port to_subnet

.. zeek:id:: to_double

   :Type: :zeek:type:`function` (str: :zeek:type:`string`) : :zeek:type:`double`

   Converts a :zeek:type:`string` to a :zeek:type:`double`.
   

   :str: The :zeek:type:`string` to convert.
   

   :returns: The :zeek:type:`string` *str* as double, or 0 if *str* has
            an invalid format.
   

.. zeek:id:: to_int

   :Type: :zeek:type:`function` (str: :zeek:type:`string`) : :zeek:type:`int`

   Converts a :zeek:type:`string` to an :zeek:type:`int`.
   

   :str: The :zeek:type:`string` to convert.
   

   :returns: The :zeek:type:`string` *str* as :zeek:type:`int`.
   
   .. zeek:see:: to_addr to_port to_subnet

.. zeek:id:: to_json

   :Type: :zeek:type:`function` (val: :zeek:type:`any`, only_loggable: :zeek:type:`bool` :zeek:attr:`&default` = ``F`` :zeek:attr:`&optional`, field_escape_pattern: :zeek:type:`pattern` :zeek:attr:`&default` = ``/^?(^_)$?/`` :zeek:attr:`&optional`) : :zeek:type:`string`

   A function to convert arbitrary Zeek data into a JSON string.
   

   :v: The value to convert to JSON.  Typically a record.
   

   :only_loggable: If the v value is a record this will only cause
                  fields with the &log attribute to be included in the JSON.
   

   :returns: a JSON formatted string.

.. zeek:id:: to_port

   :Type: :zeek:type:`function` (s: :zeek:type:`string`) : :zeek:type:`port`

   Converts a :zeek:type:`string` to a :zeek:type:`port`.
   

   :s: The :zeek:type:`string` to convert.
   

   :returns: A :zeek:type:`port` converted from *s*.
   
   .. zeek:see:: to_addr to_count to_int to_subnet

.. zeek:id:: to_subnet

   :Type: :zeek:type:`function` (sn: :zeek:type:`string`) : :zeek:type:`subnet`

   Converts a :zeek:type:`string` to a :zeek:type:`subnet`.
   

   :sn: The subnet to convert.
   

   :returns: The *sn* string as a :zeek:type:`subnet`, or the unspecified subnet
            ``::/0`` if the input string does not parse correctly.
   
   .. zeek:see:: to_count to_int to_port count_to_v4_addr raw_bytes_to_v4_addr
      to_addr

.. zeek:id:: type_name

   :Type: :zeek:type:`function` (t: :zeek:type:`any`) : :zeek:type:`string`

   Returns the type name of an arbitrary Zeek variable.
   

   :t: An arbitrary object.
   

   :returns: The type name of *t*.

.. zeek:id:: uninstall_dst_addr_filter

   :Type: :zeek:type:`function` (ip: :zeek:type:`addr`) : :zeek:type:`bool`

   Removes a destination address filter.
   

   :ip: The IP address for which a destination filter was previously installed.
   

   :returns: True on success.
   
   .. zeek:see:: Pcap::precompile_pcap_filter
                Pcap::install_pcap_filter
                install_src_addr_filter
                install_src_net_filter
                uninstall_src_addr_filter
                uninstall_src_net_filter
                install_dst_addr_filter
                install_dst_net_filter
                uninstall_dst_net_filter
                Pcap::error

.. zeek:id:: uninstall_dst_net_filter

   :Type: :zeek:type:`function` (snet: :zeek:type:`subnet`) : :zeek:type:`bool`

   Removes a destination subnet filter.
   

   :snet: The subnet for which a destination filter was previously installed.
   

   :returns: True on success.
   
   .. zeek:see:: Pcap::precompile_pcap_filter
                Pcap::install_pcap_filter
                install_src_addr_filter
                install_src_net_filter
                uninstall_src_addr_filter
                uninstall_src_net_filter
                install_dst_addr_filter
                install_dst_net_filter
                uninstall_dst_addr_filter
                Pcap::error

.. zeek:id:: uninstall_src_addr_filter

   :Type: :zeek:type:`function` (ip: :zeek:type:`addr`) : :zeek:type:`bool`

   Removes a source address filter.
   

   :ip: The IP address for which a source filter was previously installed.
   

   :returns: True on success.
   
   .. zeek:see:: Pcap::precompile_pcap_filter
                Pcap::install_pcap_filter
                install_src_addr_filter
                install_src_net_filter
                uninstall_src_net_filter
                install_dst_addr_filter
                install_dst_net_filter
                uninstall_dst_addr_filter
                uninstall_dst_net_filter
                Pcap::error

.. zeek:id:: uninstall_src_net_filter

   :Type: :zeek:type:`function` (snet: :zeek:type:`subnet`) : :zeek:type:`bool`

   Removes a source subnet filter.
   

   :snet: The subnet for which a source filter was previously installed.
   

   :returns: True on success.
   
   .. zeek:see:: Pcap::precompile_pcap_filter
                Pcap::install_pcap_filter
                install_src_addr_filter
                install_src_net_filter
                uninstall_src_addr_filter
                install_dst_addr_filter
                install_dst_net_filter
                uninstall_dst_addr_filter
                uninstall_dst_net_filter
                Pcap::error

.. zeek:id:: unique_id

   :Type: :zeek:type:`function` (prefix: :zeek:type:`string`) : :zeek:type:`string`

   Creates an identifier that is unique with high probability.
   

   :prefix: A custom string prepended to the result.
   

   :returns: A string identifier that is unique.
   
   .. zeek:see:: unique_id_from

.. zeek:id:: unique_id_from

   :Type: :zeek:type:`function` (pool: :zeek:type:`int`, prefix: :zeek:type:`string`) : :zeek:type:`string`

   Creates an identifier that is unique with high probability.
   

   :pool: A seed for determinism.
   

   :prefix: A custom string prepended to the result.
   

   :returns: A string identifier that is unique.
   
   .. zeek:see:: unique_id

.. zeek:id:: unlink

   :Type: :zeek:type:`function` (f: :zeek:type:`string`) : :zeek:type:`bool`

   Removes a file from a directory.
   

   :f: the file to delete.
   

   :returns: True if the operation succeeds and the file was deleted,
            and false if the deletion fails.
   
   .. zeek:see:: active_file open_for_append close write_file
                get_file_name set_buf flush_all enable_raw_output
                mkdir rmdir rename

.. zeek:id:: uuid_to_string

   :Type: :zeek:type:`function` (uuid: :zeek:type:`string`) : :zeek:type:`string`

   Converts a bytes representation of a UUID into its string form. For example,
   given a string of 16 bytes, it produces an output string in this format:
   ``550e8400-e29b-41d4-a716-446655440000``.
   See `<http://en.wikipedia.org/wiki/Universally_unique_identifier>`_.
   

   :uuid: The 16 bytes of the UUID.
   

   :returns: The string representation of *uuid*.

.. zeek:id:: val_size

   :Type: :zeek:type:`function` (v: :zeek:type:`any`) : :zeek:type:`count`

   Returns the number of bytes that a value occupies in memory.
   

   :v: The value
   

   :returns: The number of bytes that *v* occupies.

.. zeek:id:: write_file

   :Type: :zeek:type:`function` (f: :zeek:type:`file`, data: :zeek:type:`string`) : :zeek:type:`bool`

   Writes data to an open file.
   

   :f: A :zeek:type:`file` handle to an open file.
   

   :data: The data to write to *f*.
   

   :returns: True on success.
   
   .. zeek:see:: active_file open open_for_append close
                get_file_name set_buf flush_all mkdir enable_raw_output
                rmdir unlink rename

.. zeek:id:: zeek_is_terminating

   :Type: :zeek:type:`function` () : :zeek:type:`bool`

   Checks if Zeek is terminating.
   

   :returns: True if Zeek is in the process of shutting down.
   
   .. zeek:see:: terminate

.. zeek:id:: zeek_version

   :Type: :zeek:type:`function` () : :zeek:type:`string`

   Returns the Zeek version string.
   

   :returns: Zeek's version, e.g., 2.0-beta-47-debug.


