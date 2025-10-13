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
=============================================================== ========================================================================================
:zeek:id:`EventMetadata::current`: :zeek:type:`function`        Query the current event's metadata with identifier *id*.
:zeek:id:`EventMetadata::current_all`: :zeek:type:`function`    Query all of the current event's metadata.
:zeek:id:`EventMetadata::register`: :zeek:type:`function`       Register the expected Zeek type for event metadata.
:zeek:id:`__init_secondary_bifs`: :zeek:type:`function`         An internal function that helps initialize BIFs.
:zeek:id:`active_file`: :zeek:type:`function`                   Checks whether a given file is open.
:zeek:id:`addr_to_counts`: :zeek:type:`function`                Converts an :zeek:type:`addr` to an :zeek:type:`index_vec`.
:zeek:id:`addr_to_ptr_name`: :zeek:type:`function`              Converts an IP address to a reverse pointer name.
:zeek:id:`addr_to_subnet`: :zeek:type:`function`                Converts a :zeek:type:`addr` to a :zeek:type:`subnet`.
:zeek:id:`all_set`: :zeek:type:`function`                       Tests whether *all* elements of a boolean vector (``vector of bool``) are
                                                                true.
:zeek:id:`anonymize_addr`: :zeek:type:`function`                Anonymizes an IP address.
:zeek:id:`any_set`: :zeek:type:`function`                       Tests whether a boolean vector (``vector of bool``) has *any* true
                                                                element.
:zeek:id:`backtrace`: :zeek:type:`function`                     Returns a representation of the call stack as a vector of call stack
                                                                elements, each containing call location information.
:zeek:id:`bare_mode`: :zeek:type:`function`                     Returns whether Zeek was started in bare mode.
:zeek:id:`blocking_lookup_hostname`: :zeek:type:`function`      Issues a synchronous DNS lookup.
:zeek:id:`bytestring_to_count`: :zeek:type:`function`           Converts a string of bytes to a :zeek:type:`count`.
:zeek:id:`bytestring_to_double`: :zeek:type:`function`          Converts a string of bytes representing a double value (in network byte order)
                                                                to a :zeek:type:`double`.
:zeek:id:`bytestring_to_float`: :zeek:type:`function`           Converts a string of bytes representing a float value (in network byte order)
                                                                to a :zeek:type:`double`.
:zeek:id:`bytestring_to_hexstr`: :zeek:type:`function`          Converts a string of bytes into its hexadecimal representation.
:zeek:id:`calc_next_rotate`: :zeek:type:`function`              Calculates the duration until the next time a file is to be rotated, based
                                                                on a given rotate interval.
:zeek:id:`cat`: :zeek:type:`function`                           Returns the concatenation of the string representation of its arguments.
:zeek:id:`cat_sep`: :zeek:type:`function`                       Concatenates all arguments, with a separator placed between each one.
:zeek:id:`ceil`: :zeek:type:`function`                          Computes the smallest integer greater or equal than the given :zeek:type:`double` value.
:zeek:id:`check_subnet`: :zeek:type:`function`                  Checks if a specific subnet is a member of a set/table[subnet].
:zeek:id:`clear_table`: :zeek:type:`function`                   Removes all elements from a set or table.
:zeek:id:`close`: :zeek:type:`function`                         Closes an open file and flushes any buffered content.
:zeek:id:`compress_path`: :zeek:type:`function`                 Compresses a given path by removing '..'s and the parent directory it
                                                                references and also removing dual '/'s and extraneous '/./'s.
:zeek:id:`connection_exists`: :zeek:type:`function`             Checks whether a connection is (still) active.
:zeek:id:`continue_processing`: :zeek:type:`function`           Resumes Zeek's packet processing.
:zeek:id:`convert_for_pattern`: :zeek:type:`function`           Escapes a string so that it becomes a valid :zeek:type:`pattern` and can be
                                                                used with the :zeek:id:`string_to_pattern`.
:zeek:id:`count_to_double`: :zeek:type:`function`               Converts a :zeek:type:`count` to a :zeek:type:`double`.
:zeek:id:`count_to_port`: :zeek:type:`function`                 Converts a :zeek:type:`count` and ``transport_proto`` to a :zeek:type:`port`.
:zeek:id:`count_to_v4_addr`: :zeek:type:`function`              Converts a :zeek:type:`count` to an :zeek:type:`addr`.
:zeek:id:`counts_to_addr`: :zeek:type:`function`                Converts an :zeek:type:`index_vec` to an :zeek:type:`addr`.
:zeek:id:`current_analyzer`: :zeek:type:`function`              Returns the ID of the analyzer which raised the current event.
:zeek:id:`current_event_time`: :zeek:type:`function`            Returns the timestamp of the last raised event.
:zeek:id:`current_time`: :zeek:type:`function`                  Returns the current wall-clock time.
:zeek:id:`decode_base64`: :zeek:type:`function`                 Decodes a Base64-encoded string.
:zeek:id:`decode_base64_conn`: :zeek:type:`function`            Decodes a Base64-encoded string that was derived from processing a connection.
:zeek:id:`disable_analyzer`: :zeek:type:`function`              Disables the analyzer which raised the current event (if the analyzer
                                                                belongs to the given connection).
:zeek:id:`disable_event_group`: :zeek:type:`function`           Disabled the given event group.
:zeek:id:`disable_module_events`: :zeek:type:`function`         Disable all event handlers and hooks in the given module.
:zeek:id:`do_profiling`: :zeek:type:`function`                  Enables detailed collection of profiling statistics.
:zeek:id:`double_to_count`: :zeek:type:`function`               Converts a :zeek:type:`double` to a :zeek:type:`count`.
:zeek:id:`double_to_int`: :zeek:type:`function`                 Converts a :zeek:type:`double` to a :zeek:type:`int`.
:zeek:id:`double_to_interval`: :zeek:type:`function`            Converts a :zeek:type:`double` to an :zeek:type:`interval`.
:zeek:id:`double_to_time`: :zeek:type:`function`                Converts a :zeek:type:`double` value to a :zeek:type:`time`.
:zeek:id:`dump_current_packet`: :zeek:type:`function`           Writes the current packet to a file.
:zeek:id:`dump_packet`: :zeek:type:`function`                   Writes a given packet to a file.
:zeek:id:`dump_rule_stats`: :zeek:type:`function`               Write rule matcher statistics (DFA states, transitions, memory usage, cache
                                                                hits/misses) to a file.
:zeek:id:`enable_event_group`: :zeek:type:`function`            Enabled the given event group.
:zeek:id:`enable_module_events`: :zeek:type:`function`          Enable all event handlers and hooks in the given module.
:zeek:id:`enable_raw_output`: :zeek:type:`function`             Prevents escaping of non-ASCII characters when writing to a file.
:zeek:id:`encode_base64`: :zeek:type:`function`                 Encodes a Base64-encoded string.
:zeek:id:`entropy_test_add`: :zeek:type:`function`              Adds data to an incremental entropy calculation.
:zeek:id:`entropy_test_finish`: :zeek:type:`function`           Finishes an incremental entropy calculation.
:zeek:id:`entropy_test_init`: :zeek:type:`function`             Initializes data structures for incremental entropy calculation.
:zeek:id:`enum_names`: :zeek:type:`function`                    Returns all value names associated with an enum type.
:zeek:id:`enum_to_int`: :zeek:type:`function`                   Converts an :zeek:type:`enum` to an :zeek:type:`int`.
:zeek:id:`exit`: :zeek:type:`function`                          Shuts down the Zeek process immediately.
:zeek:id:`exp`: :zeek:type:`function`                           Computes the exponential function.
:zeek:id:`file_magic`: :zeek:type:`function`                    Determines the MIME type of a piece of data using Zeek's file magic
                                                                signatures.
:zeek:id:`file_mode`: :zeek:type:`function`                     Converts UNIX file permissions given by a mode to an ASCII string.
:zeek:id:`file_size`: :zeek:type:`function`                     Returns the size of a given file.
:zeek:id:`filter_subnet_table`: :zeek:type:`function`           For a set[subnet]/table[subnet], create a new table that contains all entries
                                                                that contain a given subnet.
:zeek:id:`find_entropy`: :zeek:type:`function`                  Performs an entropy test on the given data.
:zeek:id:`find_in_zeekpath`: :zeek:type:`function`              Determine the path used by a non-relative @load directive.
:zeek:id:`floor`: :zeek:type:`function`                         Computes the greatest integer less than the given :zeek:type:`double` value.
:zeek:id:`flush_all`: :zeek:type:`function`                     Flushes all open files to disk.
:zeek:id:`fmt`: :zeek:type:`function`                           Produces a formatted string à la ``printf``.
:zeek:id:`fnv1a32`: :zeek:type:`function`                       Returns 32-bit digest of arbitrary input values using FNV-1a hash algorithm.
:zeek:id:`fnv1a64`: :zeek:type:`function`                       Returns 64-bit digest of arbitrary input values using FNV-1a hash algorithm.
:zeek:id:`from_json`: :zeek:type:`function`                     A function to convert a JSON string into Zeek values of a given type.
:zeek:id:`generate_all_events`: :zeek:type:`function`           By default, zeek does not generate (raise) events that have not handled by
                                                                any scripts.
:zeek:id:`get_conn_transport_proto`: :zeek:type:`function`      Extracts the transport protocol from a connection.
:zeek:id:`get_current_packet`: :zeek:type:`function`            Returns the currently processed PCAP packet.
:zeek:id:`get_current_packet_header`: :zeek:type:`function`     Function to get the raw headers of the currently processed packet.
:zeek:id:`get_current_packet_ts`: :zeek:type:`function`         Returns the currently processed PCAP packet's timestamp or a 0 timestamp if
                                                                there is no packet being processed at the moment.
:zeek:id:`get_file_name`: :zeek:type:`function`                 Gets the filename associated with a file handle.
:zeek:id:`get_plugin_components`: :zeek:type:`function`         Get a list of tags available for a plugin category.
:zeek:id:`get_port_transport_proto`: :zeek:type:`function`      Extracts the transport protocol from a :zeek:type:`port`.
:zeek:id:`getenv`: :zeek:type:`function`                        Returns a system environment variable.
:zeek:id:`gethostname`: :zeek:type:`function`                   Returns the hostname of the machine Zeek runs on.
:zeek:id:`getpid`: :zeek:type:`function`                        Returns Zeek's process ID.
:zeek:id:`global_container_footprints`: :zeek:type:`function`   Generates a table of the "footprint" of all global container variables.
:zeek:id:`global_ids`: :zeek:type:`function`                    Generates a table with information about all global identifiers.
:zeek:id:`global_options`: :zeek:type:`function`                Returns a set giving the names of all global options.
:zeek:id:`has_event_group`: :zeek:type:`function`               Does an attribute event group with this name exist?
:zeek:id:`has_module_events`: :zeek:type:`function`             Does a module event group with this name exist?
:zeek:id:`have_spicy`: :zeek:type:`function`                    Returns true if Zeek was built with support for using Spicy analyzers (which
                                                                is the default).
:zeek:id:`have_spicy_analyzers`: :zeek:type:`function`          Returns true if Zeek was built with support for its in-tree Spicy analyzers
                                                                (which is the default if Spicy support is available).
:zeek:id:`haversine_distance`: :zeek:type:`function`            Calculates distance between two geographic locations using the haversine
                                                                formula.
:zeek:id:`hexstr_to_bytestring`: :zeek:type:`function`          Converts a hex-string into its binary representation.
:zeek:id:`hrw_weight`: :zeek:type:`function`                    Calculates a weight value for use in a Rendezvous Hashing algorithm.
:zeek:id:`identify_data`: :zeek:type:`function`                 Determines the MIME type of a piece of data using Zeek's file magic
                                                                signatures.
:zeek:id:`install_dst_addr_filter`: :zeek:type:`function`       Installs a filter to drop packets destined to a given IP address with
                                                                a certain probability if none of a given set of TCP flags are set.
:zeek:id:`install_dst_net_filter`: :zeek:type:`function`        Installs a filter to drop packets destined to a given subnet with
                                                                a certain probability if none of a given set of TCP flags are set.
:zeek:id:`install_src_addr_filter`: :zeek:type:`function`       Installs a filter to drop packets from a given IP source address with
                                                                a certain probability if none of a given set of TCP flags are set.
:zeek:id:`install_src_net_filter`: :zeek:type:`function`        Installs a filter to drop packets originating from a given subnet with
                                                                a certain probability if none of a given set of TCP flags are set.
:zeek:id:`int_to_count`: :zeek:type:`function`                  Converts a (positive) :zeek:type:`int` to a :zeek:type:`count`.
:zeek:id:`int_to_double`: :zeek:type:`function`                 Converts an :zeek:type:`int` to a :zeek:type:`double`.
:zeek:id:`interval_to_double`: :zeek:type:`function`            Converts an :zeek:type:`interval` to a :zeek:type:`double`.
:zeek:id:`is_event_handled`: :zeek:type:`function`              Check if an event is handled.
:zeek:id:`is_file_analyzer`: :zeek:type:`function`              Returns true if the given tag belongs to a file analyzer.
:zeek:id:`is_icmp_port`: :zeek:type:`function`                  Checks whether a given :zeek:type:`port` has ICMP as transport protocol.
:zeek:id:`is_local_interface`: :zeek:type:`function`            Checks whether a given IP address belongs to a local interface.
:zeek:id:`is_packet_analyzer`: :zeek:type:`function`            Returns true if the given tag belongs to a packet analyzer.
:zeek:id:`is_processing_suspended`: :zeek:type:`function`       Returns whether or not processing is currently suspended.
:zeek:id:`is_protocol_analyzer`: :zeek:type:`function`          Returns true if the given tag belongs to a protocol analyzer.
:zeek:id:`is_remote_event`: :zeek:type:`function`               Checks whether the current event came from a remote peer.
:zeek:id:`is_tcp_port`: :zeek:type:`function`                   Checks whether a given :zeek:type:`port` has TCP as transport protocol.
:zeek:id:`is_udp_port`: :zeek:type:`function`                   Checks whether a given :zeek:type:`port` has UDP as transport protocol.
:zeek:id:`is_v4_addr`: :zeek:type:`function`                    Returns whether an address is IPv4 or not.
:zeek:id:`is_v4_subnet`: :zeek:type:`function`                  Returns whether a subnet specification is IPv4 or not.
:zeek:id:`is_v6_addr`: :zeek:type:`function`                    Returns whether an address is IPv6 or not.
:zeek:id:`is_v6_subnet`: :zeek:type:`function`                  Returns whether a subnet specification is IPv6 or not.
:zeek:id:`is_valid_ip`: :zeek:type:`function`                   Checks if a string is a valid IPv4 or IPv6 address.
:zeek:id:`is_valid_subnet`: :zeek:type:`function`               Checks if a string is a valid IPv4 or IPv6 subnet.
:zeek:id:`ln`: :zeek:type:`function`                            Computes the natural logarithm of a number.
:zeek:id:`log10`: :zeek:type:`function`                         Computes the common logarithm of a number.
:zeek:id:`log2`: :zeek:type:`function`                          Computes the base 2 logarithm of a number.
:zeek:id:`lookup_ID`: :zeek:type:`function`                     Returns the value of a global identifier.
:zeek:id:`lookup_addr`: :zeek:type:`function`                   Issues an asynchronous reverse DNS lookup and delays the function result.
:zeek:id:`lookup_connection`: :zeek:type:`function`             Returns the :zeek:type:`connection` record for a given connection identifier.
:zeek:id:`lookup_connection_analyzer_id`: :zeek:type:`function` Returns the numeric ID of the requested protocol analyzer for the given
                                                                connection.
:zeek:id:`lookup_hostname`: :zeek:type:`function`               Issues an asynchronous DNS lookup and delays the function result.
:zeek:id:`lookup_hostname_txt`: :zeek:type:`function`           Issues an asynchronous TEXT DNS lookup and delays the function result.
:zeek:id:`mask_addr`: :zeek:type:`function`                     Masks an address down to the number of given upper bits.
:zeek:id:`match_signatures`: :zeek:type:`function`              Manually triggers the signature engine for a given connection.
:zeek:id:`matching_subnets`: :zeek:type:`function`              Gets all subnets that contain a given subnet from a set/table[subnet].
:zeek:id:`md5_hash`: :zeek:type:`function`                      Computes the MD5 hash value of the provided list of arguments.
:zeek:id:`md5_hash_finish`: :zeek:type:`function`               Returns the final MD5 digest of an incremental hash computation.
:zeek:id:`md5_hash_init`: :zeek:type:`function`                 Constructs an MD5 handle to enable incremental hash computation.
:zeek:id:`md5_hash_update`: :zeek:type:`function`               Updates the MD5 value associated with a given index.
:zeek:id:`md5_hmac`: :zeek:type:`function`                      Computes an HMAC-MD5 hash value of the provided list of arguments.
:zeek:id:`mkdir`: :zeek:type:`function`                         Creates a new directory.
:zeek:id:`network_time`: :zeek:type:`function`                  Returns the timestamp of the last packet processed.
:zeek:id:`open`: :zeek:type:`function`                          Opens a file for writing.
:zeek:id:`open_for_append`: :zeek:type:`function`               Opens a file for writing or appending.
:zeek:id:`order`: :zeek:type:`function`                         Returns the order of the elements in a vector according to some
                                                                comparison function.
:zeek:id:`packet_source`: :zeek:type:`function`                 Returns: the packet source being read by Zeek.
:zeek:id:`paraglob_equals`: :zeek:type:`function`               Compares two paraglobs for equality.
:zeek:id:`paraglob_init`: :zeek:type:`function`                 Initializes and returns a new paraglob.
:zeek:id:`paraglob_match`: :zeek:type:`function`                Gets all the patterns inside the handle associated with an input string.
:zeek:id:`piped_exec`: :zeek:type:`function`                    Opens a program with ``popen`` and writes a given string to the returned
                                                                stream to send it to the opened process's stdin.
:zeek:id:`port_to_count`: :zeek:type:`function`                 Converts a :zeek:type:`port` to a :zeek:type:`count`.
:zeek:id:`pow`: :zeek:type:`function`                           Computes the *x* raised to the power *y*.
:zeek:id:`preserve_prefix`: :zeek:type:`function`               Preserves the prefix of an IP address in anonymization.
:zeek:id:`preserve_subnet`: :zeek:type:`function`               Preserves the prefix of a subnet in anonymization.
:zeek:id:`print_raw`: :zeek:type:`function`                     Renders a sequence of values to a string of bytes and outputs them directly
                                                                to ``stdout`` with no additional escape sequences added.
:zeek:id:`ptr_name_to_addr`: :zeek:type:`function`              Converts a reverse pointer name to an address.
:zeek:id:`rand`: :zeek:type:`function`                          Generates a random number.
:zeek:id:`raw_bytes_to_v4_addr`: :zeek:type:`function`          Converts a :zeek:type:`string` of bytes into an IPv4 address.
:zeek:id:`raw_bytes_to_v6_addr`: :zeek:type:`function`          Converts a :zeek:type:`string` of bytes into an IPv6 address.
:zeek:id:`reading_live_traffic`: :zeek:type:`function`          Checks whether Zeek reads traffic from one or more network interfaces (as
                                                                opposed to from a network trace in a file).
:zeek:id:`reading_traces`: :zeek:type:`function`                Checks whether Zeek reads traffic from a trace file (as opposed to from a
                                                                network interface).
:zeek:id:`record_fields`: :zeek:type:`function`                 Generates metadata about a record's fields.
:zeek:id:`remask_addr`: :zeek:type:`function`                   Takes some top bits (such as a subnet address) from one address and the other
                                                                bits (intra-subnet part) from a second address and merges them to get a new
                                                                address.
:zeek:id:`rename`: :zeek:type:`function`                        Renames a file from src_f to dst_f.
:zeek:id:`resize`: :zeek:type:`function`                        Resizes a vector.
:zeek:id:`rmdir`: :zeek:type:`function`                         Removes a directory.
:zeek:id:`rotate_file`: :zeek:type:`function`                   Rotates a file.
:zeek:id:`rotate_file_by_name`: :zeek:type:`function`           Rotates a file identified by its name.
:zeek:id:`routing0_data_to_addrs`: :zeek:type:`function`        Converts the *data* field of :zeek:type:`ip6_routing` records that have
                                                                *rtype* of 0 into a vector of addresses.
:zeek:id:`same_object`: :zeek:type:`function`                   Checks whether two objects reference the same internal object.
:zeek:id:`set_buf`: :zeek:type:`function`                       Alters the buffering behavior of a file.
:zeek:id:`set_inactivity_timeout`: :zeek:type:`function`        Sets an individual inactivity timeout for a connection and thus
                                                                overrides the global inactivity timeout.
:zeek:id:`set_network_time`: :zeek:type:`function`              Sets the timestamp associated with the last packet processed.
:zeek:id:`set_record_packets`: :zeek:type:`function`            Controls whether packet contents belonging to a connection should be
                                                                recorded (when ``-w`` option is provided on the command line).
:zeek:id:`setenv`: :zeek:type:`function`                        Sets a system environment variable.
:zeek:id:`sha1_hash`: :zeek:type:`function`                     Computes the SHA1 hash value of the provided list of arguments.
:zeek:id:`sha1_hash_finish`: :zeek:type:`function`              Returns the final SHA1 digest of an incremental hash computation.
:zeek:id:`sha1_hash_init`: :zeek:type:`function`                Constructs an SHA1 handle to enable incremental hash computation.
:zeek:id:`sha1_hash_update`: :zeek:type:`function`              Updates the SHA1 value associated with a given index.
:zeek:id:`sha256_hash`: :zeek:type:`function`                   Computes the SHA256 hash value of the provided list of arguments.
:zeek:id:`sha256_hash_finish`: :zeek:type:`function`            Returns the final SHA256 digest of an incremental hash computation.
:zeek:id:`sha256_hash_init`: :zeek:type:`function`              Constructs an SHA256 handle to enable incremental hash computation.
:zeek:id:`sha256_hash_update`: :zeek:type:`function`            Updates the SHA256 value associated with a given index.
:zeek:id:`sha512_hash`: :zeek:type:`function`                   Computes the SHA512 hash value of the provided list of arguments.
:zeek:id:`sha512_hash_finish`: :zeek:type:`function`            Returns the final SHA512 digest of an incremental hash computation.
:zeek:id:`sha512_hash_init`: :zeek:type:`function`              Constructs an SHA512 handle to enable incremental hash computation.
:zeek:id:`sha512_hash_update`: :zeek:type:`function`            Updates the SHA512 value associated with a given index.
:zeek:id:`skip_further_processing`: :zeek:type:`function`       Informs Zeek that it should skip any further processing of the contents of
                                                                a given connection.
:zeek:id:`sleep`: :zeek:type:`function`                         Sleeps for the given amount of time.
:zeek:id:`sort`: :zeek:type:`function`                          Sorts a vector in place.
:zeek:id:`sqrt`: :zeek:type:`function`                          Computes the square root of a :zeek:type:`double`.
:zeek:id:`srand`: :zeek:type:`function`                         Sets the seed for subsequent :zeek:id:`rand` calls.
:zeek:id:`strftime`: :zeek:type:`function`                      Formats a given time value according to a format string.
:zeek:id:`string_to_pattern`: :zeek:type:`function`             Converts a :zeek:type:`string` into a :zeek:type:`pattern`.
:zeek:id:`strptime`: :zeek:type:`function`                      Parse a textual representation of a date/time value into a ``time`` type value.
:zeek:id:`subnet_to_addr`: :zeek:type:`function`                Converts a :zeek:type:`subnet` to an :zeek:type:`addr` by
                                                                extracting the prefix.
:zeek:id:`subnet_width`: :zeek:type:`function`                  Returns the width of a :zeek:type:`subnet`.
:zeek:id:`suspend_processing`: :zeek:type:`function`            Stops Zeek's packet processing.
:zeek:id:`syslog`: :zeek:type:`function`                        Send a string to syslog.
:zeek:id:`system`: :zeek:type:`function`                        Invokes a command via the ``system`` function of the OS.
:zeek:id:`system_env`: :zeek:type:`function`                    Invokes a command via the ``system`` function of the OS with a prepared
                                                                environment.
:zeek:id:`table_keys`: :zeek:type:`function`                    Gets all keys from a table.
:zeek:id:`table_pattern_matcher_stats`: :zeek:type:`function`   Return MatcherStats for a table[pattern] or set[pattern] value.
:zeek:id:`table_values`: :zeek:type:`function`                  Gets all values from a table.
:zeek:id:`terminate`: :zeek:type:`function`                     Gracefully shut down Zeek by terminating outstanding processing.
:zeek:id:`time_to_double`: :zeek:type:`function`                Converts a :zeek:type:`time` value to a :zeek:type:`double`.
:zeek:id:`to_addr`: :zeek:type:`function`                       Converts a :zeek:type:`string` to an :zeek:type:`addr`.
:zeek:id:`to_count`: :zeek:type:`function`                      Converts a :zeek:type:`string` to a :zeek:type:`count`.
:zeek:id:`to_double`: :zeek:type:`function`                     Converts a :zeek:type:`string` to a :zeek:type:`double`.
:zeek:id:`to_int`: :zeek:type:`function`                        Converts a :zeek:type:`string` to an :zeek:type:`int`.
:zeek:id:`to_json`: :zeek:type:`function`                       A function to convert arbitrary Zeek data into a JSON string.
:zeek:id:`to_port`: :zeek:type:`function`                       Converts a :zeek:type:`string` to a :zeek:type:`port`.
:zeek:id:`to_subnet`: :zeek:type:`function`                     Converts a :zeek:type:`string` to a :zeek:type:`subnet`.
:zeek:id:`type_aliases`: :zeek:type:`function`                  Returns all type name aliases of a value or type.
:zeek:id:`type_name`: :zeek:type:`function`                     Returns the type name of an arbitrary Zeek variable.
:zeek:id:`uninstall_dst_addr_filter`: :zeek:type:`function`     Removes a destination address filter.
:zeek:id:`uninstall_dst_net_filter`: :zeek:type:`function`      Removes a destination subnet filter.
:zeek:id:`uninstall_src_addr_filter`: :zeek:type:`function`     Removes a source address filter.
:zeek:id:`uninstall_src_net_filter`: :zeek:type:`function`      Removes a source subnet filter.
:zeek:id:`unique_id`: :zeek:type:`function`                     Creates an identifier that is unique with high probability.
:zeek:id:`unique_id_from`: :zeek:type:`function`                Creates an identifier that is unique with high probability.
:zeek:id:`unlink`: :zeek:type:`function`                        Removes a file from a directory.
:zeek:id:`uuid_to_string`: :zeek:type:`function`                Converts a bytes representation of a UUID into its string form.
:zeek:id:`val_footprint`: :zeek:type:`function`                 Computes a value's "footprint": the number of objects the value contains
                                                                either directly or indirectly.
:zeek:id:`write_file`: :zeek:type:`function`                    Writes data to an open file.
:zeek:id:`zeek_args`: :zeek:type:`function`                     Returns: list of command-line arguments (``argv``) used to run Zeek.
:zeek:id:`zeek_is_terminating`: :zeek:type:`function`           Checks if Zeek is terminating.
:zeek:id:`zeek_version`: :zeek:type:`function`                  Returns the Zeek version string.
=============================================================== ========================================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Functions
#########
.. zeek:id:: EventMetadata::current
   :source-code: base/bif/zeek.bif.zeek 90 90

   :Type: :zeek:type:`function` (id: :zeek:type:`EventMetadata::ID`) : :zeek:type:`any_vec`

   Query the current event's metadata with identifier *id*.
   

   :param id: The metadata identifier, e.g. ``EventMetadata::NETWORK_TIMESTAMP``.
   

   :returns: A vector of values. The vector is empty if no metadata with
            the given identifier is attached to this event, otherwise a
            vector whose elements are of the type used during registration.
   
   .. zeek:see:: EventMetadata::register EventMetadata::current_all

.. zeek:id:: EventMetadata::current_all
   :source-code: base/bif/zeek.bif.zeek 99 99

   :Type: :zeek:type:`function` () : :zeek:type:`event_metadata_vec`

   Query all of the current event's metadata.
   

   :returns: A vector :zeek:see:`EventMetadata::Entry` elements holding all
            the metadata attached to this event.
   
   .. zeek:see:: EventMetadata::register EventMetadata::current

.. zeek:id:: EventMetadata::register
   :source-code: base/bif/zeek.bif.zeek 78 78

   :Type: :zeek:type:`function` (id: :zeek:type:`EventMetadata::ID`, t: :zeek:type:`any`) : :zeek:type:`bool`

   Register the expected Zeek type for event metadata.
   

   :param id: The event metadata identifier.
   

   :param t: A type expression or type alias. The type cannot be ``any``, ``func``,
      ``file``, ``opaque`` or a composite type containing one of these types.
   

   :returns: true if the registration was successful, false if *id* is
            registered with a different type already, or type is invalid.
   
   .. zeek:see:: EventMetadata::current EventMetadata::current_all

.. zeek:id:: __init_secondary_bifs
   :source-code: base/bif/zeek.bif.zeek 2656 2656

   :Type: :zeek:type:`function` () : :zeek:type:`bool`

   An internal function that helps initialize BIFs.

.. zeek:id:: active_file
   :source-code: base/bif/zeek.bif.zeek 2336 2336

   :Type: :zeek:type:`function` (f: :zeek:type:`file`) : :zeek:type:`bool`

   Checks whether a given file is open.
   

   :param f: The file to check.
   

   :returns: True if *f* is an open :zeek:type:`file`.
   
   .. todo:: Rename to ``is_open``.

.. zeek:id:: addr_to_counts
   :source-code: base/bif/zeek.bif.zeek 1326 1326

   :Type: :zeek:type:`function` (a: :zeek:type:`addr`) : :zeek:type:`index_vec`

   Converts an :zeek:type:`addr` to an :zeek:type:`index_vec`.
   

   :param a: The address to convert into a vector of counts.
   

   :returns: A vector containing the host-order address representation,
            four elements in size for IPv6 addresses, or one element for IPv4.
   
   .. zeek:see:: counts_to_addr

.. zeek:id:: addr_to_ptr_name
   :source-code: base/bif/zeek.bif.zeek 1668 1668

   :Type: :zeek:type:`function` (a: :zeek:type:`addr`) : :zeek:type:`string`

   Converts an IP address to a reverse pointer name. For example,
   ``192.168.0.1`` to ``1.0.168.192.in-addr.arpa``.
   

   :param a: The IP address to convert to a reverse pointer name.
   

   :returns: The reverse pointer representation of *a*.
   
   .. zeek:see:: ptr_name_to_addr to_addr

.. zeek:id:: addr_to_subnet
   :source-code: base/bif/zeek.bif.zeek 1534 1534

   :Type: :zeek:type:`function` (a: :zeek:type:`addr`) : :zeek:type:`subnet`

   Converts a :zeek:type:`addr` to a :zeek:type:`subnet`.
   

   :param a: The address to convert.
   

   :returns: The address as a :zeek:type:`subnet`.
   
   .. zeek:see:: to_subnet

.. zeek:id:: all_set
   :source-code: base/bif/zeek.bif.zeek 838 838

   :Type: :zeek:type:`function` (v: :zeek:type:`any`) : :zeek:type:`bool`

   Tests whether *all* elements of a boolean vector (``vector of bool``) are
   true.
   

   :param v: The boolean vector instance.
   

   :returns: True iff all elements in *v* are true or there are no elements.
   
   .. zeek:see:: any_set
   
   .. note::
   
        Missing elements count as false.

.. zeek:id:: anonymize_addr
   :source-code: base/bif/zeek.bif.zeek 2709 2709

   :Type: :zeek:type:`function` (a: :zeek:type:`addr`, cl: :zeek:type:`IPAddrAnonymizationClass`) : :zeek:type:`addr`

   Anonymizes an IP address.
   

   :param a: The address to anonymize.
   

   :param cl: The anonymization class, which can take on three different values:
   
       - ``ORIG_ADDR``: Tag *a* as an originator address.
   
       - ``RESP_ADDR``: Tag *a* as an responder address.
   
       - ``OTHER_ADDR``: Tag *a* as an arbitrary address.
   

   :returns: An anonymized version of *a*.
   
   .. zeek:see:: preserve_prefix preserve_subnet
   
   .. todo:: Currently dysfunctional.

.. zeek:id:: any_set
   :source-code: base/bif/zeek.bif.zeek 823 823

   :Type: :zeek:type:`function` (v: :zeek:type:`any`) : :zeek:type:`bool`

   Tests whether a boolean vector (``vector of bool``) has *any* true
   element.
   

   :param v: The boolean vector instance.
   

   :returns: True if any element in *v* is true.
   
   .. zeek:see:: all_set

.. zeek:id:: backtrace
   :source-code: base/bif/zeek.bif.zeek 1299 1299

   :Type: :zeek:type:`function` () : :zeek:type:`Backtrace`

   Returns a representation of the call stack as a vector of call stack
   elements, each containing call location information.
   

   :returns: the call stack information, including function, file, and line
            location information.

.. zeek:id:: bare_mode
   :source-code: base/bif/zeek.bif.zeek 1076 1076

   :Type: :zeek:type:`function` () : :zeek:type:`bool`

   Returns whether Zeek was started in bare mode.
   

   :returns: True if Zeek was started in bare mode, false otherwise.

.. zeek:id:: blocking_lookup_hostname
   :source-code: base/bif/zeek.bif.zeek 2066 2066

   :Type: :zeek:type:`function` (host: :zeek:type:`string`) : :zeek:type:`addr_set`

   Issues a synchronous DNS lookup.
   

   :param host: The hostname to lookup.
   

   :returns: A set addresses, either IPv4 or IPv6, associated with *host*.
   
   .. zeek:see:: lookup_addr
   
   .. note::
   
        This is a blocking call. You should use :zeek:see:`lookup_hostname`
        unless for initialization or testing purposes.
   
   .. zeek:see:: lookup_addr lookup_hostname

.. zeek:id:: bytestring_to_count
   :source-code: base/bif/zeek.bif.zeek 1646 1646

   :Type: :zeek:type:`function` (s: :zeek:type:`string`, is_le: :zeek:type:`bool` :zeek:attr:`&default` = ``F`` :zeek:attr:`&optional`) : :zeek:type:`count`

   Converts a string of bytes to a :zeek:type:`count`.
   

   :param s: A string of bytes containing the binary representation of the value.
   

   :param is_le: If true, *s* is assumed to be in little endian format, else it's big endian.
   

   :returns: The value contained in *s*, or 0 if the conversion failed.
   

.. zeek:id:: bytestring_to_double
   :source-code: base/bif/zeek.bif.zeek 1622 1622

   :Type: :zeek:type:`function` (s: :zeek:type:`string`) : :zeek:type:`double`

   Converts a string of bytes representing a double value (in network byte order)
   to a :zeek:type:`double`. This is similar to :zeek:id:`bytestring_to_float`
   but works on 8-byte strings.
   

   :param s: A string of bytes containing the binary representation of a double value.
   

   :returns: The double value contained in *s*, or 0 if the conversion
            failed.
   
   .. zeek:see:: bytestring_to_float

.. zeek:id:: bytestring_to_float
   :source-code: base/bif/zeek.bif.zeek 1635 1635

   :Type: :zeek:type:`function` (s: :zeek:type:`string`) : :zeek:type:`double`

   Converts a string of bytes representing a float value (in network byte order)
   to a :zeek:type:`double`. This is similar to :zeek:id:`bytestring_to_double`
   but works on 4-byte strings.
   

   :param s: A string of bytes containing the binary representation of a float value.
   

   :returns: The float value contained in *s*, or 0 if the conversion
            failed.
   
   .. zeek:see:: bytestring_to_double

.. zeek:id:: bytestring_to_hexstr
   :source-code: base/bif/zeek.bif.zeek 1679 1679

   :Type: :zeek:type:`function` (bytestring: :zeek:type:`string`) : :zeek:type:`string`

   Converts a string of bytes into its hexadecimal representation.
   For example, ``"04"`` would be converted to ``"3034"``.
   

   :param bytestring: The string of bytes.
   

   :returns: The hexadecimal representation of *bytestring*.
   
   .. zeek:see:: hexdump hexstr_to_bytestring

.. zeek:id:: calc_next_rotate
   :source-code: base/bif/zeek.bif.zeek 2379 2379

   :Type: :zeek:type:`function` (i: :zeek:type:`interval`) : :zeek:type:`interval`

   Calculates the duration until the next time a file is to be rotated, based
   on a given rotate interval.
   

   :param i: The rotate interval to base the calculation on.
   

   :returns: The duration until the next file rotation time.
   
   .. zeek:see:: rotate_file rotate_file_by_name

.. zeek:id:: cat
   :source-code: base/bif/zeek.bif.zeek 882 882

   :Type: :zeek:type:`function` (...) : :zeek:type:`string`

   Returns the concatenation of the string representation of its arguments. The
   arguments can be of any type. For example, ``cat("foo", 3, T)`` returns
   ``"foo3T"``.
   

   :returns: A string concatenation of all arguments.

.. zeek:id:: cat_sep
   :source-code: base/bif/zeek.bif.zeek 898 898

   :Type: :zeek:type:`function` (...) : :zeek:type:`string`

   Concatenates all arguments, with a separator placed between each one. This
   function is similar to :zeek:id:`cat`, but places a separator between each
   given argument. If any of the variable arguments is an empty string it is
   replaced by the given default string instead.
   

   :param sep: The separator to place between each argument.
   

   :param def: The default string to use when an argument is the empty string.
   

   :returns: A concatenation of all arguments with *sep* between each one and
            empty strings replaced with *def*.
   
   .. zeek:see:: cat string_cat

.. zeek:id:: ceil
   :source-code: base/bif/zeek.bif.zeek 979 979

   :Type: :zeek:type:`function` (d: :zeek:type:`double`) : :zeek:type:`double`

   Computes the smallest integer greater or equal than the given :zeek:type:`double` value.
   For example, ``ceil(3.14)`` returns ``4.0``, and ``ceil(-3.14)``
   returns ``-3.0``.
   

   :param d: The :zeek:type:`double` to manipulate.
   

   :returns: The next lowest integer of *d* as :zeek:type:`double`.
   
   .. zeek:see:: floor sqrt exp ln log2 log10 pow

.. zeek:id:: check_subnet
   :source-code: base/bif/zeek.bif.zeek 790 790

   :Type: :zeek:type:`function` (search: :zeek:type:`subnet`, t: :zeek:type:`any`) : :zeek:type:`bool`

   Checks if a specific subnet is a member of a set/table[subnet].
   In contrast to the ``in`` operator, this performs an exact match, not
   a longest prefix match.
   

   :param search: the subnet to search for.
   

   :param t: the set[subnet] or table[subnet].
   

   :returns: True if the exact subnet is a member, false otherwise.

.. zeek:id:: clear_table
   :source-code: base/bif/zeek.bif.zeek 737 737

   :Type: :zeek:type:`function` (v: :zeek:type:`any`) : :zeek:type:`any`

   Removes all elements from a set or table.
   

   :param v: The set or table

.. zeek:id:: close
   :source-code: base/bif/zeek.bif.zeek 2233 2233

   :Type: :zeek:type:`function` (f: :zeek:type:`file`) : :zeek:type:`bool`

   Closes an open file and flushes any buffered content.
   

   :param f: A :zeek:type:`file` handle to an open file.
   

   :returns: True on success.
   
   .. zeek:see:: active_file open open_for_append write_file
                get_file_name set_buf flush_all mkdir enable_raw_output
                rmdir unlink rename

.. zeek:id:: compress_path
   :source-code: base/bif/zeek.bif.zeek 2772 2772

   :Type: :zeek:type:`function` (dir: :zeek:type:`string`) : :zeek:type:`string`

   Compresses a given path by removing '..'s and the parent directory it
   references and also removing dual '/'s and extraneous '/./'s.
   

   :param dir: a path string, either relative or absolute.
   

   :returns: a compressed version of the input path.

.. zeek:id:: connection_exists
   :source-code: base/bif/zeek.bif.zeek 1906 1906

   :Type: :zeek:type:`function` (c: :zeek:type:`conn_id`) : :zeek:type:`bool`

   Checks whether a connection is (still) active.
   

   :param c: The connection id to check.
   

   :returns: True if the connection identified by *c* exists.
   
   .. zeek:see:: lookup_connection

.. zeek:id:: continue_processing
   :source-code: base/bif/zeek.bif.zeek 2611 2611

   :Type: :zeek:type:`function` () : :zeek:type:`any`

   Resumes Zeek's packet processing.
   
   .. zeek:see:: suspend_processing
                 is_processing_suspended

.. zeek:id:: convert_for_pattern
   :source-code: base/bif/zeek.bif.zeek 1765 1765

   :Type: :zeek:type:`function` (s: :zeek:type:`string`) : :zeek:type:`string`

   Escapes a string so that it becomes a valid :zeek:type:`pattern` and can be
   used with the :zeek:id:`string_to_pattern`. Any character from the set
   ``^$-:"\/|*+?.(){}[]`` is prefixed with a ``\``.
   

   :param s: The string to escape.
   

   :returns: An escaped version of *s* that has the structure of a valid
            :zeek:type:`pattern`.
   
   .. zeek:see:: string_to_pattern
   

.. zeek:id:: count_to_double
   :source-code: base/bif/zeek.bif.zeek 1422 1422

   :Type: :zeek:type:`function` (c: :zeek:type:`count`) : :zeek:type:`double`

   Converts a :zeek:type:`count` to a :zeek:type:`double`.
   

   :param c: The :zeek:type:`count` to convert.
   

   :returns: The :zeek:type:`count` *c* as :zeek:type:`double`.
   
   .. zeek:see:: int_to_double double_to_count

.. zeek:id:: count_to_port
   :source-code: base/bif/zeek.bif.zeek 1484 1484

   :Type: :zeek:type:`function` (num: :zeek:type:`count`, proto: :zeek:type:`transport_proto`) : :zeek:type:`port`

   Converts a :zeek:type:`count` and ``transport_proto`` to a :zeek:type:`port`.
   

   :param num: The :zeek:type:`port` number.
   

   :param proto: The transport protocol.
   

   :returns: The :zeek:type:`count` *num* as :zeek:type:`port`.
   
   .. zeek:see:: port_to_count

.. zeek:id:: count_to_v4_addr
   :source-code: base/bif/zeek.bif.zeek 1575 1575

   :Type: :zeek:type:`function` (ip: :zeek:type:`count`) : :zeek:type:`addr`

   Converts a :zeek:type:`count` to an :zeek:type:`addr`.
   

   :param ip: The :zeek:type:`count` to convert.
   

   :returns: The :zeek:type:`count` *ip* as :zeek:type:`addr`.
   
   .. zeek:see:: raw_bytes_to_v4_addr to_addr to_subnet raw_bytes_to_v6_addr

.. zeek:id:: counts_to_addr
   :source-code: base/bif/zeek.bif.zeek 1337 1337

   :Type: :zeek:type:`function` (v: :zeek:type:`index_vec`) : :zeek:type:`addr`

   Converts an :zeek:type:`index_vec` to an :zeek:type:`addr`.
   

   :param v: The vector containing host-order IP address representation,
      one element for IPv4 addresses, four elements for IPv6 addresses.
   

   :returns: An IP address.
   
   .. zeek:see:: addr_to_counts

.. zeek:id:: current_analyzer
   :source-code: base/bif/zeek.bif.zeek 1054 1054

   :Type: :zeek:type:`function` () : :zeek:type:`count`

   Returns the ID of the analyzer which raised the current event.
   

   :returns: The ID of the analyzer which raised the current event, or 0 if
            none.

.. zeek:id:: current_event_time
   :source-code: base/bif/zeek.bif.zeek 64 64

   :Type: :zeek:type:`function` () : :zeek:type:`time`

   Returns the timestamp of the last raised event. The timestamp reflects the
   network time the event was intended to be executed. For scheduled events,
   this is the time the event was scheduled for. For any other event, this is
   the time when the event was created.
   

   :returns: The timestamp of the last raised event.
   
   .. zeek:see:: current_time set_network_time

.. zeek:id:: current_time
   :source-code: base/bif/zeek.bif.zeek 32 32

   :Type: :zeek:type:`function` () : :zeek:type:`time`

   Returns the current wall-clock time.
   
   In general, you should use :zeek:id:`network_time` instead
   unless you are using Zeek for non-networking uses (such as general
   scripting; not particularly recommended), because otherwise your script
   may behave very differently on live traffic versus played-back traffic
   from a save file.
   

   :returns: The wall-clock time.
   
   .. zeek:see:: network_time set_network_time

.. zeek:id:: decode_base64
   :source-code: base/bif/zeek.bif.zeek 1719 1719

   :Type: :zeek:type:`function` (s: :zeek:type:`string`, a: :zeek:type:`string` :zeek:attr:`&default` = ``""`` :zeek:attr:`&optional`) : :zeek:type:`string`

   Decodes a Base64-encoded string.
   

   :param s: The Base64-encoded string.
   

   :param a: An optional custom alphabet. The empty string indicates the default
      alphabet. If given, the string must consist of 64 unique characters.
   

   :returns: The decoded version of *s*.
   
   .. zeek:see:: decode_base64_conn encode_base64

.. zeek:id:: decode_base64_conn
   :source-code: base/bif/zeek.bif.zeek 1736 1736

   :Type: :zeek:type:`function` (cid: :zeek:type:`conn_id`, s: :zeek:type:`string`, a: :zeek:type:`string` :zeek:attr:`&default` = ``""`` :zeek:attr:`&optional`) : :zeek:type:`string`

   Decodes a Base64-encoded string that was derived from processing a connection.
   If an error is encountered decoding the string, that will be logged to
   ``weird.log`` with the associated connection.
   

   :param cid: The identifier of the connection that the encoding originates from.
   

   :param s: The Base64-encoded string.
   

   :param a: An optional custom alphabet. The empty string indicates the default
      alphabet. If given, the string must consist of 64 unique characters.
   

   :returns: The decoded version of *s*.
   
   .. zeek:see:: decode_base64

.. zeek:id:: disable_analyzer
   :source-code: base/bif/zeek.bif.zeek 2138 2138

   :Type: :zeek:type:`function` (cid: :zeek:type:`conn_id`, aid: :zeek:type:`count`, err_if_no_conn: :zeek:type:`bool` :zeek:attr:`&default` = ``T`` :zeek:attr:`&optional`, prevent: :zeek:type:`bool` :zeek:attr:`&default` = ``F`` :zeek:attr:`&optional`) : :zeek:type:`bool`

   Disables the analyzer which raised the current event (if the analyzer
   belongs to the given connection).
   

   :param cid: The connection identifier.
   

   :param aid: The analyzer ID.
   

   :param err_if_no_conn: Emit an error message if the connection does not exit.
   

   :param prevent: Prevent the same analyzer type from being attached in the future.
            This is useful for preventing the same analyzer from being
            automatically reattached in the future, e.g. as a result of a
            DPD signature suddenly matching.
   

   :returns: True if the connection identified by *cid* exists and has analyzer
            *aid* and it is scheduled for removal.
   
   .. zeek:see:: Analyzer::schedule_analyzer Analyzer::name

.. zeek:id:: disable_event_group
   :source-code: base/bif/zeek.bif.zeek 2822 2822

   :Type: :zeek:type:`function` (group: :zeek:type:`string`) : :zeek:type:`bool`

   Disabled the given event group.
   
   All event and hook handlers with a matching :zeek:attr:`&group` attribute
   will be disabled if not already disabled through another group.
   

   :param group: The group to disable.
   
   .. zeek:see:: enable_event_group disable_event_group has_event_group
                 enable_module_events disable_module_events has_module_events

.. zeek:id:: disable_module_events
   :source-code: base/bif/zeek.bif.zeek 2854 2854

   :Type: :zeek:type:`function` (module_name: :zeek:type:`string`) : :zeek:type:`bool`

   Disable all event handlers and hooks in the given module.
   
   All event handlers and hooks defined in the given module will be disabled.
   

   :param module_name: The module to disable.
   
   .. zeek:see:: enable_event_group disable_event_group has_event_group
                 enable_module_events disable_module_events has_module_events

.. zeek:id:: do_profiling
   :source-code: base/bif/zeek.bif.zeek 1224 1224

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
   :source-code: base/bif/zeek.bif.zeek 1388 1388

   :Type: :zeek:type:`function` (d: :zeek:type:`double`) : :zeek:type:`count`

   Converts a :zeek:type:`double` to a :zeek:type:`count`.
   

   :param d: The :zeek:type:`double` to convert.
   

   :returns: The :zeek:type:`double` *d* as unsigned integer, or 0 if *d* < 0.0.
            The value returned follows typical rounding rules, as implemented
            by rint().

.. zeek:id:: double_to_int
   :source-code: base/bif/zeek.bif.zeek 1378 1378

   :Type: :zeek:type:`function` (d: :zeek:type:`double`) : :zeek:type:`int`

   Converts a :zeek:type:`double` to a :zeek:type:`int`.
   

   :param d: The :zeek:type:`double` to convert.
   

   :returns: The :zeek:type:`double` *d* as signed integer. The value returned
            follows typical rounding rules, as implemented by rint().
   
   .. zeek:see:: double_to_time

.. zeek:id:: double_to_interval
   :source-code: base/bif/zeek.bif.zeek 1462 1462

   :Type: :zeek:type:`function` (d: :zeek:type:`double`) : :zeek:type:`interval`

   Converts a :zeek:type:`double` to an :zeek:type:`interval`.
   

   :param d: The :zeek:type:`double` to convert.
   

   :returns: The :zeek:type:`double` *d* as :zeek:type:`interval`.
   
   .. zeek:see:: interval_to_double

.. zeek:id:: double_to_time
   :source-code: base/bif/zeek.bif.zeek 1452 1452

   :Type: :zeek:type:`function` (d: :zeek:type:`double`) : :zeek:type:`time`

   Converts a :zeek:type:`double` value to a :zeek:type:`time`.
   

   :param d: The :zeek:type:`double` to convert.
   

   :returns: The :zeek:type:`double` value *d* as :zeek:type:`time`.
   
   .. zeek:see:: time_to_double double_to_count

.. zeek:id:: dump_current_packet
   :source-code: base/bif/zeek.bif.zeek 1934 1934

   :Type: :zeek:type:`function` (file_name: :zeek:type:`string`) : :zeek:type:`bool`

   Writes the current packet to a file.
   

   :param file_name: The name of the file to write the packet to.
   

   :returns: True on success.
   
   .. zeek:see:: dump_packet get_current_packet
   
   .. note::
   
        See :zeek:see:`get_current_packet` for caveats.

.. zeek:id:: dump_packet
   :source-code: base/bif/zeek.bif.zeek 2011 2011

   :Type: :zeek:type:`function` (pkt: :zeek:type:`pcap_packet`, file_name: :zeek:type:`string`) : :zeek:type:`bool`

   Writes a given packet to a file.
   

   :param pkt: The PCAP packet.
   

   :param file_name: The name of the file to write *pkt* to.
   

   :returns: True on success
   
   .. zeek:see:: get_current_packet dump_current_packet

.. zeek:id:: dump_rule_stats
   :source-code: base/bif/zeek.bif.zeek 1243 1243

   :Type: :zeek:type:`function` (f: :zeek:type:`file`) : :zeek:type:`bool`

   Write rule matcher statistics (DFA states, transitions, memory usage, cache
   hits/misses) to a file.
   

   :param f: The file to write to.
   

   :returns: True (unconditionally).
   
   .. zeek:see:: get_matcher_stats

.. zeek:id:: enable_event_group
   :source-code: base/bif/zeek.bif.zeek 2810 2810

   :Type: :zeek:type:`function` (group: :zeek:type:`string`) : :zeek:type:`bool`

   Enabled the given event group.
   
   All event and hook handlers with a matching :zeek:attr:`&group` attribute
   will be enabled if this group was the last disabled group of these handlers.
   

   :param group: The group to enable.
   
   .. zeek:see:: enable_event_group disable_event_group has_event_group
                 enable_module_events disable_module_events has_module_events

.. zeek:id:: enable_module_events
   :source-code: base/bif/zeek.bif.zeek 2843 2843

   :Type: :zeek:type:`function` (module_name: :zeek:type:`string`) : :zeek:type:`bool`

   Enable all event handlers and hooks in the given module.
   
   All event handlers and hooks defined in the given module will be enabled
   if not disabled otherwise through an event group.
   

   :param module_name: The module to enable.
   
   .. zeek:see:: enable_event_group disable_event_group has_event_group
                 enable_module_events disable_module_events has_module_events

.. zeek:id:: enable_raw_output
   :source-code: base/bif/zeek.bif.zeek 2394 2394

   :Type: :zeek:type:`function` (f: :zeek:type:`file`) : :zeek:type:`any`

   Prevents escaping of non-ASCII characters when writing to a file.
   This function is equivalent to :zeek:attr:`&raw_output`.
   

   :param f: The file to disable raw output for.

.. zeek:id:: encode_base64
   :source-code: base/bif/zeek.bif.zeek 1706 1706

   :Type: :zeek:type:`function` (s: :zeek:type:`string`, a: :zeek:type:`string` :zeek:attr:`&default` = ``""`` :zeek:attr:`&optional`) : :zeek:type:`string`

   Encodes a Base64-encoded string.
   

   :param s: The string to encode.
   

   :param a: An optional custom alphabet. The empty string indicates the default
      alphabet. If given, the string must consist of 64 unique characters.
   

   :returns: The encoded version of *s*.
   
   .. zeek:see:: decode_base64

.. zeek:id:: entropy_test_add
   :source-code: base/bif/zeek.bif.zeek 690 690

   :Type: :zeek:type:`function` (handle: :zeek:type:`opaque` of entropy, data: :zeek:type:`string`) : :zeek:type:`bool`

   Adds data to an incremental entropy calculation.
   

   :param handle: The opaque handle representing the entropy calculation state.
   

   :param data: The data to add to the entropy calculation.
   

   :returns: True on success.
   
   .. zeek:see:: find_entropy entropy_test_add entropy_test_finish

.. zeek:id:: entropy_test_finish
   :source-code: base/bif/zeek.bif.zeek 703 703

   :Type: :zeek:type:`function` (handle: :zeek:type:`opaque` of entropy) : :zeek:type:`entropy_test_result`

   Finishes an incremental entropy calculation. Before using this function,
   one needs to obtain an opaque handle with :zeek:id:`entropy_test_init` and
   add data to it via :zeek:id:`entropy_test_add`.
   

   :param handle: The opaque handle representing the entropy calculation state.
   

   :returns: The result of the entropy test. See :zeek:id:`find_entropy` for a
            description of the individual components.
   
   .. zeek:see:: find_entropy entropy_test_init entropy_test_add

.. zeek:id:: entropy_test_init
   :source-code: base/bif/zeek.bif.zeek 678 678

   :Type: :zeek:type:`function` () : :zeek:type:`opaque` of entropy

   Initializes data structures for incremental entropy calculation.
   

   :returns: An opaque handle to be used in subsequent operations.
   
   .. zeek:see:: find_entropy entropy_test_add entropy_test_finish

.. zeek:id:: enum_names
   :source-code: base/bif/zeek.bif.zeek 1114 1114

   :Type: :zeek:type:`function` (et: :zeek:type:`any`) : :zeek:type:`string_set`

   Returns all value names associated with an enum type.
   

   :param et: An enum type or a string naming one.
   

   :returns: All enum value names associated with enum type *et*.
            If *et* is not an enum type or does not name one, an empty set is returned.

.. zeek:id:: enum_to_int
   :source-code: base/bif/zeek.bif.zeek 1345 1345

   :Type: :zeek:type:`function` (e: :zeek:type:`any`) : :zeek:type:`int`

   Converts an :zeek:type:`enum` to an :zeek:type:`int`.
   

   :param e: The :zeek:type:`enum` to convert.
   

   :returns: The :zeek:type:`int` value that corresponds to the :zeek:type:`enum`.

.. zeek:id:: exit
   :source-code: base/bif/zeek.bif.zeek 130 130

   :Type: :zeek:type:`function` (code: :zeek:type:`int`) : :zeek:type:`any`

   Shuts down the Zeek process immediately.
   

   :param code: The exit code to return with.
   
   .. zeek:see:: terminate

.. zeek:id:: exp
   :source-code: base/bif/zeek.bif.zeek 999 999

   :Type: :zeek:type:`function` (d: :zeek:type:`double`) : :zeek:type:`double`

   Computes the exponential function.
   

   :param d: The argument to the exponential function.
   

   :returns: *e* to the power of *d*.
   
   .. zeek:see:: floor ceil sqrt ln log2 log10 pow

.. zeek:id:: file_magic
   :source-code: base/bif/zeek.bif.zeek 627 627

   :Type: :zeek:type:`function` (data: :zeek:type:`string`) : :zeek:type:`mime_matches`

   Determines the MIME type of a piece of data using Zeek's file magic
   signatures.
   

   :param data: The data for which to find matching MIME types.
   

   :returns: All matching signatures, in order of strength.
   
   .. zeek:see:: identify_data

.. zeek:id:: file_mode
   :source-code: base/bif/zeek.bif.zeek 2094 2094

   :Type: :zeek:type:`function` (mode: :zeek:type:`count`) : :zeek:type:`string`

   Converts UNIX file permissions given by a mode to an ASCII string.
   

   :param mode: The permissions (an octal number like 0644 converted to decimal).
   

   :returns: A string representation of *mode* in the format
            ``rw[xsS]rw[xsS]rw[xtT]``.

.. zeek:id:: file_size
   :source-code: base/bif/zeek.bif.zeek 2387 2387

   :Type: :zeek:type:`function` (f: :zeek:type:`string`) : :zeek:type:`double`

   Returns the size of a given file.
   

   :param f: The name of the file whose size to lookup.
   

   :returns: The size of *f* in bytes.

.. zeek:id:: filter_subnet_table
   :source-code: base/bif/zeek.bif.zeek 778 778

   :Type: :zeek:type:`function` (search: :zeek:type:`subnet`, t: :zeek:type:`any`) : :zeek:type:`any`

   For a set[subnet]/table[subnet], create a new table that contains all entries
   that contain a given subnet.
   

   :param search: the subnet to search for.
   

   :param t: the set[subnet] or table[subnet].
   

   :returns: A new table that contains all the entries that cover the subnet searched for.

.. zeek:id:: find_entropy
   :source-code: base/bif/zeek.bif.zeek 670 670

   :Type: :zeek:type:`function` (data: :zeek:type:`string`) : :zeek:type:`entropy_test_result`

   Performs an entropy test on the given data.
   See http://www.fourmilab.ch/random.
   

   :param data: The data to compute the entropy for.
   

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

.. zeek:id:: find_in_zeekpath
   :source-code: base/bif/zeek.bif.zeek 2904 2904

   :Type: :zeek:type:`function` (p: :zeek:type:`string`) : :zeek:type:`string`

   Determine the path used by a non-relative @load directive.
   
   This function is package aware: Passing *package* will yield the
   path to *package.zeek*, *package/__load__.zeek* or an empty string
   if neither can be found. Note that passing a relative path or absolute
   path is an error.
   

   :param path: The filename, package or path to search for in ZEEKPATH.
   

   :returns: Path of script file that would be loaded by an @load directive.

.. zeek:id:: floor
   :source-code: base/bif/zeek.bif.zeek 967 967

   :Type: :zeek:type:`function` (d: :zeek:type:`double`) : :zeek:type:`double`

   Computes the greatest integer less than the given :zeek:type:`double` value.
   For example, ``floor(3.14)`` returns ``3.0``, and ``floor(-3.14)``
   returns ``-4.0``.
   

   :param d: The :zeek:type:`double` to manipulate.
   

   :returns: The next lowest integer of *d* as :zeek:type:`double`.
   
   .. zeek:see:: ceil sqrt exp ln log2 log10 pow

.. zeek:id:: flush_all
   :source-code: base/bif/zeek.bif.zeek 2272 2272

   :Type: :zeek:type:`function` () : :zeek:type:`bool`

   Flushes all open files to disk.
   

   :returns: True on success.
   
   .. zeek:see:: active_file open open_for_append close
                get_file_name write_file set_buf mkdir enable_raw_output
                rmdir unlink rename

.. zeek:id:: fmt
   :source-code: base/bif/zeek.bif.zeek 939 939

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
   :source-code: base/bif/zeek.bif.zeek 540 540

   :Type: :zeek:type:`function` (input: :zeek:type:`any`) : :zeek:type:`count`

   Returns 32-bit digest of arbitrary input values using FNV-1a hash algorithm.
   See `<https://en.wikipedia.org/wiki/Fowler%E2%80%93Noll%E2%80%93Vo_hash_function>`_.
   

   :param input: The desired input value to hash.
   

   :returns: The hashed value.
   
   .. zeek:see:: hrw_weight

.. zeek:id:: fnv1a64
   :source-code: base/bif/zeek.bif.zeek 549 549

   :Type: :zeek:type:`function` (input: :zeek:type:`any`) : :zeek:type:`count`

   Returns 64-bit digest of arbitrary input values using FNV-1a hash algorithm.
   See `<https://en.wikipedia.org/wiki/Fowler%E2%80%93Noll%E2%80%93Vo_hash_function>`_.
   

   :param input: The desired input value to hash.
   

   :returns: The hashed value.

.. zeek:id:: from_json
   :source-code: base/bif/zeek.bif.zeek 2763 2763

   :Type: :zeek:type:`function` (s: :zeek:type:`string`, t: :zeek:type:`any`, key_func: :zeek:type:`string_mapper` :zeek:attr:`&default` = :zeek:see:`from_json_default_key_mapper` :zeek:attr:`&optional`) : :zeek:type:`from_json_result`

   A function to convert a JSON string into Zeek values of a given type.
   
   Implicit conversion from JSON to Zeek types is implemented for:
   
     - bool
     - int, count, real
     - interval from numbers as seconds
     - time from numbers as unix timestamp
     - port from strings in "80/tcp" notation
     - addr, subnet
     - enum
     - sets
     - vectors
     - records (from JSON objects)
   
   Optional or default record fields are allowed to be missing or null in the input.
   

   :param s: The JSON string to parse.
   

   :param t: Type of Zeek data.
   

   :param key_func: Optional function to normalize key names in JSON objects. Useful
             when keys are not valid field identifiers, or represent reserved
             keywords like **port** or **type**.
   

   :param returns: A record with the result of the conversion, containing either a value or an error message.
   
   .. zeek:see:: to_json

.. zeek:id:: generate_all_events
   :source-code: base/bif/zeek.bif.zeek 2638 2638

   :Type: :zeek:type:`function` () : :zeek:type:`bool`

   By default, zeek does not generate (raise) events that have not handled by
   any scripts. This means that these events will be invisible to a lot of other
   event handlers - and will not raise :zeek:id:`new_event`.
   
   Calling this function will cause all event handlers to be raised. This is, likely,
   only useful for debugging and causes reduced performance.

.. zeek:id:: get_conn_transport_proto
   :source-code: base/bif/zeek.bif.zeek 1885 1885

   :Type: :zeek:type:`function` (cid: :zeek:type:`conn_id`) : :zeek:type:`transport_proto`

   Extracts the transport protocol from a connection.
   

   :param cid: The connection identifier.
   

   :returns: The transport protocol of the connection identified by *cid*.
   
   .. zeek:see:: get_port_transport_proto
                get_orig_seq get_resp_seq

.. zeek:id:: get_current_packet
   :source-code: base/bif/zeek.bif.zeek 1960 1960

   :Type: :zeek:type:`function` () : :zeek:type:`pcap_packet`

   Returns the currently processed PCAP packet.
   

   :returns: The currently processed packet, which is a record
            containing the timestamp, ``snaplen``, and packet data.
   
   .. zeek:see:: dump_current_packet dump_packet
   
   .. note::
   
        Calling ``get_current_packet()`` within events that are not directly
        raised as a result of processing a specific packet may result in
        unexpected behavior. For example, out-of-order TCP segments or IP
        defragmentation may result in such scenarios. Details depend on the
        involved packet and protocol analyzers. As a rule of thumb, in low-level
        events, like :zeek:see:`raw_packet`, the behavior is well defined.
   
        The returned packet is directly taken from the packet source and any
        tunnel or encapsulation layers will be present in the payload. Correctly
        inspecting the payload using Zeek script is therefore a non-trivial task.
   
        The return value of ``get_current_packet()`` further should be considered
        undefined when called within event handlers raised via :zeek:see:`event`,
        :zeek:see:`schedule` or by recipient of Broker messages.

.. zeek:id:: get_current_packet_header
   :source-code: base/bif/zeek.bif.zeek 1983 1983

   :Type: :zeek:type:`function` () : :zeek:type:`raw_pkt_hdr`

   Function to get the raw headers of the currently processed packet.
   

   :returns: The :zeek:type:`raw_pkt_hdr` record containing the Layer 2, 3 and
            4 headers of the currently processed packet.
   
   .. zeek:see:: raw_pkt_hdr get_current_packet
   
   .. note::
   
        See :zeek:see:`get_current_packet` for caveats.
   
   .. note::
   
        Zeek currently does not expose individual IP datagram fragments to the
        script-layer. Therefore, this function either returns the original header
        of a non-fragmented IP datagram, or, if the last fragment has been received,
        the header of a reassembled datagram. A reassembled IP datagram's header can
        be recognized by ``MF=T`` in the ``ip`` field. The ``ip$len`` field for a
        reassembled IP datagram represents the first fragment's header length plus
        the sum of the individual fragment data lengths.

.. zeek:id:: get_current_packet_ts
   :source-code: base/bif/zeek.bif.zeek 1999 1999

   :Type: :zeek:type:`function` () : :zeek:type:`time`

   Returns the currently processed PCAP packet's timestamp or a 0 timestamp if
   there is no packet being processed at the moment.
   

   :returns: The currently processed packet's timestamp.
   
   .. zeek:see:: get_current_packet get_current_packet_header network_time
   
   .. note::
   
        When there is no packet being processed, ``get_current_packet_ts()``
        will return a 0 timestamp, while ``network_time()`` will return the
        timestamp of the last processed packet until it falls back to tracking
        wall clock after ``packet_source_inactivity_timeout``.

.. zeek:id:: get_file_name
   :source-code: base/bif/zeek.bif.zeek 2346 2346

   :Type: :zeek:type:`function` (f: :zeek:type:`file`) : :zeek:type:`string`

   Gets the filename associated with a file handle.
   

   :param f: The file handle to inquire the name for.
   

   :returns: The filename associated with *f*.
   
   .. zeek:see:: open

.. zeek:id:: get_plugin_components
   :source-code: base/bif/zeek.bif.zeek 2913 2913

   :Type: :zeek:type:`function` (category: :zeek:type:`string`) : :zeek:type:`plugin_component_vec`

   Get a list of tags available for a plugin category.
   

   :param category: The plugin category to request tags for.
   

   :returns: A vector of records containing the tags of all plugin components
            that belong to the specified category.

.. zeek:id:: get_port_transport_proto
   :source-code: base/bif/zeek.bif.zeek 1896 1896

   :Type: :zeek:type:`function` (p: :zeek:type:`port`) : :zeek:type:`transport_proto`

   Extracts the transport protocol from a :zeek:type:`port`.
   

   :param p: The port.
   

   :returns: The transport protocol of the port *p*.
   
   .. zeek:see:: get_conn_transport_proto
                get_orig_seq get_resp_seq

.. zeek:id:: getenv
   :source-code: base/bif/zeek.bif.zeek 110 110

   :Type: :zeek:type:`function` (var: :zeek:type:`string`) : :zeek:type:`string`

   Returns a system environment variable.
   

   :param var: The name of the variable whose value to request.
   

   :returns: The system environment variable identified by *var*, or an empty
            string if it is not defined.
   
   .. zeek:see:: setenv

.. zeek:id:: gethostname
   :source-code: base/bif/zeek.bif.zeek 1257 1257

   :Type: :zeek:type:`function` () : :zeek:type:`string`

   Returns the hostname of the machine Zeek runs on.
   

   :returns: The hostname of the machine Zeek runs on.

.. zeek:id:: getpid
   :source-code: base/bif/zeek.bif.zeek 1060 1060

   :Type: :zeek:type:`function` () : :zeek:type:`count`

   Returns Zeek's process ID.
   

   :returns: Zeek's process ID.

.. zeek:id:: global_container_footprints
   :source-code: base/bif/zeek.bif.zeek 1156 1156

   :Type: :zeek:type:`function` () : :zeek:type:`var_sizes`

   Generates a table of the "footprint" of all global container variables.
   This is (approximately) the number of objects the global contains either
   directly or indirectly.  The number is not meant to be precise, but
   rather comparable: larger footprint correlates with more memory consumption.
   The table index is the variable name and the value is the footprint.
   

   :returns: A table that maps variable names to their footprints.
   
   .. zeek:see:: val_footprint

.. zeek:id:: global_ids
   :source-code: base/bif/zeek.bif.zeek 1179 1179

   :Type: :zeek:type:`function` () : :zeek:type:`id_table`

   Generates a table with information about all global identifiers. The table
   value is a record containing the type name of the identifier, whether it is
   exported, a constant, an enum constant, redefinable, and its value (if it
   has one).
   
   Module names are included in the returned table as well. The ``type_name``
   field is set to  "module" and their names are prefixed with "module " to avoid
   clashing with global identifiers. Note that there is no module type in Zeek.
   

   :returns: A table that maps identifier names to information about them.

.. zeek:id:: global_options
   :source-code: base/bif/zeek.bif.zeek 1183 1183

   :Type: :zeek:type:`function` () : :zeek:type:`string_set`

   Returns a set giving the names of all global options.

.. zeek:id:: has_event_group
   :source-code: base/bif/zeek.bif.zeek 2831 2831

   :Type: :zeek:type:`function` (group: :zeek:type:`string`) : :zeek:type:`bool`

   Does an attribute event group with this name exist?
   

   :param group: The group name.
   
   .. zeek:see:: enable_event_group disable_event_group has_event_group
                 enable_module_events disable_module_events has_module_events

.. zeek:id:: has_module_events
   :source-code: base/bif/zeek.bif.zeek 2863 2863

   :Type: :zeek:type:`function` (group: :zeek:type:`string`) : :zeek:type:`bool`

   Does a module event group with this name exist?
   

   :param group: The group name.
   
   .. zeek:see:: enable_event_group disable_event_group has_event_group
                 enable_module_events disable_module_events has_module_events

.. zeek:id:: have_spicy
   :source-code: base/bif/zeek.bif.zeek 2868 2868

   :Type: :zeek:type:`function` () : :zeek:type:`bool`

   Returns true if Zeek was built with support for using Spicy analyzers (which
   is the default).

.. zeek:id:: have_spicy_analyzers
   :source-code: base/bif/zeek.bif.zeek 2873 2873

   :Type: :zeek:type:`function` () : :zeek:type:`bool`

   Returns true if Zeek was built with support for its in-tree Spicy analyzers
   (which is the default if Spicy support is available).

.. zeek:id:: haversine_distance
   :source-code: base/bif/zeek.bif.zeek 2085 2085

   :Type: :zeek:type:`function` (lat1: :zeek:type:`double`, long1: :zeek:type:`double`, lat2: :zeek:type:`double`, long2: :zeek:type:`double`) : :zeek:type:`double`

   Calculates distance between two geographic locations using the haversine
   formula.  Latitudes and longitudes must be given in degrees, where southern
   hemisphere latitudes are negative and western hemisphere longitudes are
   negative.
   

   :param lat1: Latitude (in degrees) of location 1.
   

   :param long1: Longitude (in degrees) of location 1.
   

   :param lat2: Latitude (in degrees) of location 2.
   

   :param long2: Longitude (in degrees) of location 2.
   

   :returns: Distance in miles.
   
   .. zeek:see:: haversine_distance_ip

.. zeek:id:: hexstr_to_bytestring
   :source-code: base/bif/zeek.bif.zeek 1693 1693

   :Type: :zeek:type:`function` (hexstr: :zeek:type:`string`) : :zeek:type:`string`

   Converts a hex-string into its binary representation.
   For example, ``"3034"`` would be converted to ``"04"``.
   
   The input string is assumed to contain an even number of hexadecimal digits
   (0-9, a-f, or A-F), otherwise behavior is undefined.
   

   :param hexstr: The hexadecimal string representation.
   

   :returns: The binary representation of *hexstr*.
   
   .. zeek:see:: hexdump bytestring_to_hexstr

.. zeek:id:: hrw_weight
   :source-code: base/bif/zeek.bif.zeek 565 565

   :Type: :zeek:type:`function` (key_digest: :zeek:type:`count`, site_id: :zeek:type:`count`) : :zeek:type:`count`

   Calculates a weight value for use in a Rendezvous Hashing algorithm.
   See `<https://en.wikipedia.org/wiki/Rendezvous_hashing>`_.
   The weight function used is the one recommended in the original

   :param paper: `<http://www.eecs.umich.edu/techreports/cse/96/CSE-TR-316-96.pdf>`_.
   

   :param key_digest: A 32-bit digest of a key.  E.g. use :zeek:see:`fnv1a32` to
               produce this.
   

   :param site_id: A 32-bit site/node identifier.
   

   :returns: The weight value for the key/site pair.
   
   .. zeek:see:: fnv1a32

.. zeek:id:: identify_data
   :source-code: base/bif/zeek.bif.zeek 616 616

   :Type: :zeek:type:`function` (data: :zeek:type:`string`, return_mime: :zeek:type:`bool` :zeek:attr:`&default` = ``T`` :zeek:attr:`&optional`) : :zeek:type:`string`

   Determines the MIME type of a piece of data using Zeek's file magic
   signatures.
   

   :param data: The data to find the MIME type for.
   

   :param return_mime: Deprecated argument; does nothing, except emit a warning
                when false.
   

   :returns: The MIME type of *data*, or "<unknown>" if there was an error
            or no match.  This is the strongest signature match.
   
   .. zeek:see:: file_magic

.. zeek:id:: install_dst_addr_filter
   :source-code: base/bif/zeek.bif.zeek 2524 2524

   :Type: :zeek:type:`function` (ip: :zeek:type:`addr`, tcp_flags: :zeek:type:`count`, prob: :zeek:type:`double`) : :zeek:type:`bool`

   Installs a filter to drop packets destined to a given IP address with
   a certain probability if none of a given set of TCP flags are set.
   Note that for IPv6 packets with a routing type header and non-zero
   segments left, this filters out against the final destination of the
   packet according to the routing extension header.
   

   :param ip: Drop packets to this IP address.
   

   :param tcp_flags: If none of these TCP flags are set, drop packets to *ip* with
              probability *prob*.
   

   :param prob: The probability [0.0, 1.0] used to drop packets to *ip*.
   

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
   :source-code: base/bif/zeek.bif.zeek 2551 2551

   :Type: :zeek:type:`function` (snet: :zeek:type:`subnet`, tcp_flags: :zeek:type:`count`, prob: :zeek:type:`double`) : :zeek:type:`bool`

   Installs a filter to drop packets destined to a given subnet with
   a certain probability if none of a given set of TCP flags are set.
   

   :param snet: Drop packets to this subnet.
   

   :param tcp_flags: If none of these TCP flags are set, drop packets to *snet* with
              probability *prob*.
   

   :param prob: The probability [0.0, 1.0] used to drop packets to *snet*.
   

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
   :source-code: base/bif/zeek.bif.zeek 2429 2429

   :Type: :zeek:type:`function` (ip: :zeek:type:`addr`, tcp_flags: :zeek:type:`count`, prob: :zeek:type:`double`) : :zeek:type:`bool`

   Installs a filter to drop packets from a given IP source address with
   a certain probability if none of a given set of TCP flags are set.
   Note that for IPv6 packets with a Destination options header that has
   the Home Address option, this filters out against that home address.
   

   :param ip: The IP address to drop.
   

   :param tcp_flags: If none of these TCP flags are set, drop packets from *ip* with
              probability *prob*.
   

   :param prob: The probability [0.0, 1.0] used to drop packets from *ip*.
   

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
   :source-code: base/bif/zeek.bif.zeek 2456 2456

   :Type: :zeek:type:`function` (snet: :zeek:type:`subnet`, tcp_flags: :zeek:type:`count`, prob: :zeek:type:`double`) : :zeek:type:`bool`

   Installs a filter to drop packets originating from a given subnet with
   a certain probability if none of a given set of TCP flags are set.
   

   :param snet: The subnet to drop packets from.
   

   :param tcp_flags: If none of these TCP flags are set, drop packets from *snet* with
              probability *prob*.
   

   :param prob: The probability [0.0, 1.0] used to drop packets from *snet*.
   

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
   :source-code: base/bif/zeek.bif.zeek 1367 1367

   :Type: :zeek:type:`function` (n: :zeek:type:`int`) : :zeek:type:`count`

   Converts a (positive) :zeek:type:`int` to a :zeek:type:`count`.
   

   :param n: The :zeek:type:`int` to convert.
   

   :returns: The :zeek:type:`int` *n* as unsigned integer, or 0 if *n* < 0.

.. zeek:id:: int_to_double
   :source-code: base/bif/zeek.bif.zeek 1432 1432

   :Type: :zeek:type:`function` (i: :zeek:type:`int`) : :zeek:type:`double`

   Converts an :zeek:type:`int` to a :zeek:type:`double`.
   

   :param i: The :zeek:type:`int` to convert.
   

   :returns: The :zeek:type:`int` *i* as :zeek:type:`double`.
   
   .. zeek:see:: count_to_double double_to_count

.. zeek:id:: interval_to_double
   :source-code: base/bif/zeek.bif.zeek 1412 1412

   :Type: :zeek:type:`function` (i: :zeek:type:`interval`) : :zeek:type:`double`

   Converts an :zeek:type:`interval` to a :zeek:type:`double`.
   

   :param i: The :zeek:type:`interval` to convert.
   

   :returns: The :zeek:type:`interval` *i* as :zeek:type:`double`.
   
   .. zeek:see:: double_to_interval

.. zeek:id:: is_event_handled
   :source-code: base/bif/zeek.bif.zeek 2650 2650

   :Type: :zeek:type:`function` (event_name: :zeek:type:`string`) : :zeek:type:`bool`

   Check if an event is handled. Typically this means that a script defines an event.
   This currently is mainly used to warn when events are defined that will not be used
   in certain conditions.
   
   Raises an error if the named event does not exist.
   

   :param event_name: event name to check
   

   :param returns: true if the named event is handled.

.. zeek:id:: is_file_analyzer
   :source-code: base/bif/zeek.bif.zeek 2788 2788

   :Type: :zeek:type:`function` (atype: :zeek:type:`AllAnalyzers::Tag`) : :zeek:type:`bool`

   Returns true if the given tag belongs to a file analyzer.
   

   :param atype: The analyzer tag to check.
   

   :returns: true if *atype* is a tag of a file analyzer, else false.

.. zeek:id:: is_icmp_port
   :source-code: base/bif/zeek.bif.zeek 1872 1872

   :Type: :zeek:type:`function` (p: :zeek:type:`port`) : :zeek:type:`bool`

   Checks whether a given :zeek:type:`port` has ICMP as transport protocol.
   

   :param p: The :zeek:type:`port` to check.
   

   :returns: True iff *p* is an ICMP port.
   
   .. zeek:see:: is_tcp_port is_udp_port

.. zeek:id:: is_local_interface
   :source-code: base/bif/zeek.bif.zeek 1232 1232

   :Type: :zeek:type:`function` (ip: :zeek:type:`addr`) : :zeek:type:`bool`

   Checks whether a given IP address belongs to a local interface.
   

   :param ip: The IP address to check.
   

   :returns: True if *ip* belongs to a local interface.

.. zeek:id:: is_packet_analyzer
   :source-code: base/bif/zeek.bif.zeek 2796 2796

   :Type: :zeek:type:`function` (atype: :zeek:type:`AllAnalyzers::Tag`) : :zeek:type:`bool`

   Returns true if the given tag belongs to a packet analyzer.
   

   :param atype: The analyzer type to check.
   

   :returns: true if *atype* is a tag of a packet analyzer, else false.

.. zeek:id:: is_processing_suspended
   :source-code: base/bif/zeek.bif.zeek 2618 2618

   :Type: :zeek:type:`function` () : :zeek:type:`bool`

   Returns whether or not processing is currently suspended.
   
   .. zeek:see:: suspend_processing
                 continue_processing

.. zeek:id:: is_protocol_analyzer
   :source-code: base/bif/zeek.bif.zeek 2780 2780

   :Type: :zeek:type:`function` (atype: :zeek:type:`AllAnalyzers::Tag`) : :zeek:type:`bool`

   Returns true if the given tag belongs to a protocol analyzer.
   

   :param atype: The analyzer tag to check.
   

   :returns: true if *atype* is a tag of a protocol analyzer, else false.

.. zeek:id:: is_remote_event
   :source-code: base/bif/zeek.bif.zeek 2595 2595

   :Type: :zeek:type:`function` () : :zeek:type:`bool`

   Checks whether the current event came from a remote peer.
   

   :returns: True if the current event came from a remote peer.

.. zeek:id:: is_tcp_port
   :source-code: base/bif/zeek.bif.zeek 1852 1852

   :Type: :zeek:type:`function` (p: :zeek:type:`port`) : :zeek:type:`bool`

   Checks whether a given :zeek:type:`port` has TCP as transport protocol.
   

   :param p: The :zeek:type:`port` to check.
   

   :returns: True iff *p* is a TCP port.
   
   .. zeek:see:: is_udp_port is_icmp_port

.. zeek:id:: is_udp_port
   :source-code: base/bif/zeek.bif.zeek 1862 1862

   :Type: :zeek:type:`function` (p: :zeek:type:`port`) : :zeek:type:`bool`

   Checks whether a given :zeek:type:`port` has UDP as transport protocol.
   

   :param p: The :zeek:type:`port` to check.
   

   :returns: True iff *p* is a UDP port.
   
   .. zeek:see:: is_icmp_port is_tcp_port

.. zeek:id:: is_v4_addr
   :source-code: base/bif/zeek.bif.zeek 1265 1265

   :Type: :zeek:type:`function` (a: :zeek:type:`addr`) : :zeek:type:`bool`

   Returns whether an address is IPv4 or not.
   

   :param a: the address to check.
   

   :returns: true if *a* is an IPv4 address, else false.

.. zeek:id:: is_v4_subnet
   :source-code: base/bif/zeek.bif.zeek 1281 1281

   :Type: :zeek:type:`function` (s: :zeek:type:`subnet`) : :zeek:type:`bool`

   Returns whether a subnet specification is IPv4 or not.
   

   :param s: the subnet to check.
   

   :returns: true if *s* is an IPv4 subnet, else false.

.. zeek:id:: is_v6_addr
   :source-code: base/bif/zeek.bif.zeek 1273 1273

   :Type: :zeek:type:`function` (a: :zeek:type:`addr`) : :zeek:type:`bool`

   Returns whether an address is IPv6 or not.
   

   :param a: the address to check.
   

   :returns: true if *a* is an IPv6 address, else false.

.. zeek:id:: is_v6_subnet
   :source-code: base/bif/zeek.bif.zeek 1289 1289

   :Type: :zeek:type:`function` (s: :zeek:type:`subnet`) : :zeek:type:`bool`

   Returns whether a subnet specification is IPv6 or not.
   

   :param s: the subnet to check.
   

   :returns: true if *s* is an IPv6 subnet, else false.

.. zeek:id:: is_valid_ip
   :source-code: base/bif/zeek.bif.zeek 1504 1504

   :Type: :zeek:type:`function` (ip: :zeek:type:`string`) : :zeek:type:`bool`

   Checks if a string is a valid IPv4 or IPv6 address.
   

   :param ip: the string to check for valid IP formatting.
   

   :returns: T if the string is a valid IPv4 or IPv6 address format.

.. zeek:id:: is_valid_subnet
   :source-code: base/bif/zeek.bif.zeek 1512 1512

   :Type: :zeek:type:`function` (cidr: :zeek:type:`string`) : :zeek:type:`bool`

   Checks if a string is a valid IPv4 or IPv6 subnet.
   

   :param cidr: the string to check for valid subnet formatting.
   

   :returns: T if the string is a valid IPv4 or IPv6 subnet format.

.. zeek:id:: ln
   :source-code: base/bif/zeek.bif.zeek 1009 1009

   :Type: :zeek:type:`function` (d: :zeek:type:`double`) : :zeek:type:`double`

   Computes the natural logarithm of a number.
   

   :param d: The argument to the logarithm.
   

   :returns: The natural logarithm of *d*.
   
   .. zeek:see:: floor ceil sqrt exp log2 log10 pow

.. zeek:id:: log10
   :source-code: base/bif/zeek.bif.zeek 1029 1029

   :Type: :zeek:type:`function` (d: :zeek:type:`double`) : :zeek:type:`double`

   Computes the common logarithm of a number.
   

   :param d: The argument to the logarithm.
   

   :returns: The common logarithm of *d*.
   
   .. zeek:see:: floor ceil sqrt exp ln log2 pow

.. zeek:id:: log2
   :source-code: base/bif/zeek.bif.zeek 1019 1019

   :Type: :zeek:type:`function` (d: :zeek:type:`double`) : :zeek:type:`double`

   Computes the base 2 logarithm of a number.
   

   :param d: The argument to the logarithm.
   

   :returns: The base 2 logarithm of *d*.
   
   .. zeek:see:: floor ceil sqrt exp ln log10 pow

.. zeek:id:: lookup_ID
   :source-code: base/bif/zeek.bif.zeek 1192 1192

   :Type: :zeek:type:`function` (id: :zeek:type:`string`) : :zeek:type:`any`

   Returns the value of a global identifier.
   

   :param id: The global identifier.
   

   :returns: The value of *id*. If *id* does not describe a valid identifier,
            the string ``"<unknown id>"`` or ``"<no ID value>"`` is returned.

.. zeek:id:: lookup_addr
   :source-code: base/bif/zeek.bif.zeek 2025 2025

   :Type: :zeek:type:`function` (host: :zeek:type:`addr`) : :zeek:type:`string`

   Issues an asynchronous reverse DNS lookup and delays the function result.
   This function can therefore only be called inside a ``when`` condition,
   e.g., ``when ( local host = lookup_addr(10.0.0.1) ) { f(host); }``.
   

   :param host: The IP address to lookup.
   

   :returns: The DNS name of *host*.
   
   .. zeek:see:: lookup_hostname

.. zeek:id:: lookup_connection
   :source-code: base/bif/zeek.bif.zeek 1918 1918

   :Type: :zeek:type:`function` (cid: :zeek:type:`conn_id`) : :zeek:type:`connection`

   Returns the :zeek:type:`connection` record for a given connection identifier.
   

   :param cid: The connection ID.
   

   :returns: The :zeek:type:`connection` record for *cid*. If *cid* does not point
            to an existing connection, the function generates a run-time error
            and returns a dummy value.
   
   .. zeek:see:: connection_exists

.. zeek:id:: lookup_connection_analyzer_id
   :source-code: base/bif/zeek.bif.zeek 2117 2117

   :Type: :zeek:type:`function` (cid: :zeek:type:`conn_id`, atype: :zeek:type:`AllAnalyzers::Tag`) : :zeek:type:`count`

   Returns the numeric ID of the requested protocol analyzer for the given
   connection.
   

   :param cid: The connection identifier.
   

   :param atype: The analyzer tag, such as ``Analyzer::ANALYZER_HTTP``.
   

   :returns: a numeric identifier for the analyzer, valid for the given
            connection. When no such analyzer exists the function returns
            0, which is never a valid analyzer ID value.
   
   .. zeek:see:: disable_analyzer Analyzer::disabling_analyzer

.. zeek:id:: lookup_hostname
   :source-code: base/bif/zeek.bif.zeek 2049 2049

   :Type: :zeek:type:`function` (host: :zeek:type:`string`) : :zeek:type:`addr_set`

   Issues an asynchronous DNS lookup and delays the function result.
   This function can therefore only be called inside a ``when`` condition,
   e.g., ``when ( local h = lookup_hostname("www.zeek.org") ) { f(h); }``.
   

   :param host: The hostname to lookup.
   

   :returns: A set of DNS A and AAAA records associated with *host*.
   
   .. zeek:see:: lookup_addr blocking_lookup_hostname

.. zeek:id:: lookup_hostname_txt
   :source-code: base/bif/zeek.bif.zeek 2037 2037

   :Type: :zeek:type:`function` (host: :zeek:type:`string`) : :zeek:type:`string`

   Issues an asynchronous TEXT DNS lookup and delays the function result.
   This function can therefore only be called inside a ``when`` condition,
   e.g., ``when ( local h = lookup_hostname_txt("www.zeek.org") ) { f(h); }``.
   

   :param host: The hostname to lookup.
   

   :returns: The DNS TXT record associated with *host*.
   
   .. zeek:see:: lookup_hostname

.. zeek:id:: mask_addr
   :source-code: base/bif/zeek.bif.zeek 1822 1822

   :Type: :zeek:type:`function` (a: :zeek:type:`addr`, top_bits_to_keep: :zeek:type:`count`) : :zeek:type:`subnet`

   Masks an address down to the number of given upper bits. For example,
   ``mask_addr(1.2.3.4, 18)`` returns ``1.2.0.0``.
   

   :param a: The address to mask.
   

   :param top_bits_to_keep: The number of top bits to keep in *a*; must be greater
                     than 0 and less than 33 for IPv4, or 129 for IPv6.
   

   :returns: The address *a* masked down to *top_bits_to_keep* bits.
   
   .. zeek:see:: remask_addr

.. zeek:id:: match_signatures
   :source-code: base/bif/zeek.bif.zeek 2629 2629

   :Type: :zeek:type:`function` (c: :zeek:type:`connection`, pattern_type: :zeek:type:`int`, s: :zeek:type:`string`, bol: :zeek:type:`bool`, eol: :zeek:type:`bool`, from_orig: :zeek:type:`bool`, clear: :zeek:type:`bool`) : :zeek:type:`bool`

   Manually triggers the signature engine for a given connection.
   This is an internal function.

.. zeek:id:: matching_subnets
   :source-code: base/bif/zeek.bif.zeek 767 767

   :Type: :zeek:type:`function` (search: :zeek:type:`subnet`, t: :zeek:type:`any`) : :zeek:type:`subnet_vec`

   Gets all subnets that contain a given subnet from a set/table[subnet].
   

   :param search: the subnet to search for.
   

   :param t: the set[subnet] or table[subnet].
   

   :returns: All the keys of the set or table that cover the subnet searched for.

.. zeek:id:: md5_hash
   :source-code: base/bif/zeek.bif.zeek 224 224

   :Type: :zeek:type:`function` (...) : :zeek:type:`string`

   Computes the MD5 hash value of the provided list of arguments.
   

   :returns: The MD5 hash value of the concatenated arguments.
   
   .. zeek:see:: md5_hmac md5_hash_init md5_hash_update md5_hash_finish
      sha1_hash sha1_hash_init sha1_hash_update sha1_hash_finish
      sha256_hash sha256_hash_init sha256_hash_update sha256_hash_finish
      sha512_hash_init sha512_hash_update sha512_hash_finish
   
   .. note::
   
        This function performs a one-shot computation of its arguments.
        For incremental hash computation, see :zeek:id:`md5_hash_init` and
        friends.

.. zeek:id:: md5_hash_finish
   :source-code: base/bif/zeek.bif.zeek 454 454

   :Type: :zeek:type:`function` (handle: :zeek:type:`opaque` of md5) : :zeek:type:`string`

   Returns the final MD5 digest of an incremental hash computation.
   

   :param handle: The opaque handle associated with this hash computation.
   

   :returns: The hash value associated with the computation of *handle*.
   
   .. zeek:see:: md5_hmac md5_hash md5_hash_init md5_hash_update
      sha1_hash sha1_hash_init sha1_hash_update sha1_hash_finish
      sha256_hash sha256_hash_init sha256_hash_update sha256_hash_finish
      sha512_hash sha512_hash_update sha512_hash_finish

.. zeek:id:: md5_hash_init
   :source-code: base/bif/zeek.bif.zeek 309 309

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
   :source-code: base/bif/zeek.bif.zeek 390 390

   :Type: :zeek:type:`function` (handle: :zeek:type:`opaque` of md5, data: :zeek:type:`string`) : :zeek:type:`bool`

   Updates the MD5 value associated with a given index. It is required to
   call :zeek:id:`md5_hash_init` once before calling this
   function.
   

   :param handle: The opaque handle associated with this hash computation.
   

   :param data: The data to add to the hash computation.
   

   :returns: True on success.
   
   .. zeek:see:: md5_hmac md5_hash md5_hash_init md5_hash_finish
      sha1_hash sha1_hash_init sha1_hash_update sha1_hash_finish
      sha256_hash sha256_hash_init sha256_hash_update sha256_hash_finish
      sha512_hash sha512_hash_update sha512_hash_finish

.. zeek:id:: md5_hmac
   :source-code: base/bif/zeek.bif.zeek 288 288

   :Type: :zeek:type:`function` (...) : :zeek:type:`string`

   Computes an HMAC-MD5 hash value of the provided list of arguments. The HMAC
   secret key is generated from available entropy when Zeek starts up, or it can
   be specified for repeatability using the ``-K`` command line flag.
   

   :returns: The HMAC-MD5 hash value of the concatenated arguments.
   
   .. zeek:see:: md5_hash md5_hash_init md5_hash_update md5_hash_finish
      sha1_hash sha1_hash_init sha1_hash_update sha1_hash_finish
      sha256_hash sha256_hash_init sha256_hash_update sha256_hash_finish
      sha512_hash_init sha512_hash_update sha512_hash_finish

.. zeek:id:: mkdir
   :source-code: base/bif/zeek.bif.zeek 2285 2285

   :Type: :zeek:type:`function` (f: :zeek:type:`string`) : :zeek:type:`bool`

   Creates a new directory.
   

   :param f: The directory name.
   

   :returns: True if the operation succeeds or if *f* already exists,
            and false if the file creation fails.
   
   .. zeek:see:: active_file open_for_append close write_file
                get_file_name set_buf flush_all enable_raw_output
                rmdir unlink rename

.. zeek:id:: network_time
   :source-code: base/bif/zeek.bif.zeek 42 42

   :Type: :zeek:type:`function` () : :zeek:type:`time`

   Returns the timestamp of the last packet processed. This function returns
   the timestamp of the most recently read packet, whether read from a
   live network interface or from a save file.
   

   :returns: The timestamp of the packet processed.
   
   .. zeek:see:: current_time set_network_time

.. zeek:id:: open
   :source-code: base/bif/zeek.bif.zeek 2208 2208

   :Type: :zeek:type:`function` (f: :zeek:type:`string`) : :zeek:type:`file`

   Opens a file for writing. If a file with the same name already exists, this
   function overwrites it (as opposed to :zeek:id:`open_for_append`).
   

   :param f: The path to the file.
   

   :returns: A :zeek:type:`file` handle for subsequent operations.
   
   .. zeek:see:: active_file open_for_append close write_file
                get_file_name set_buf flush_all mkdir enable_raw_output
                rmdir unlink rename

.. zeek:id:: open_for_append
   :source-code: base/bif/zeek.bif.zeek 2221 2221

   :Type: :zeek:type:`function` (f: :zeek:type:`string`) : :zeek:type:`file`

   Opens a file for writing or appending. If a file with the same name already
   exists, this function appends to it (as opposed to :zeek:id:`open`).
   

   :param f: The path to the file.
   

   :returns: A :zeek:type:`file` handle for subsequent operations.
   
   .. zeek:see:: active_file open close write_file
                get_file_name set_buf flush_all mkdir enable_raw_output
                rmdir unlink rename

.. zeek:id:: order
   :source-code: base/bif/zeek.bif.zeek 868 868

   :Type: :zeek:type:`function` (...) : :zeek:type:`index_vec`

   Returns the order of the elements in a vector according to some
   comparison function. See :zeek:id:`sort` for details about the comparison
   function.
   

   :param v: The vector whose order to compute.
   

   :returns: A ``vector of count`` with the indices of the ordered elements.
            For example, the elements of *v* in order are (assuming ``o``
            is the vector returned by ``order``):  v[o[0]], v[o[1]], etc.
   
   .. zeek:see:: sort

.. zeek:id:: packet_source
   :source-code: base/bif/zeek.bif.zeek 1144 1144

   :Type: :zeek:type:`function` () : :zeek:type:`PacketSource`


   :returns: the packet source being read by Zeek.
   
   .. zeek:see:: reading_live_traffic reading_traces

.. zeek:id:: paraglob_equals
   :source-code: base/bif/zeek.bif.zeek 527 527

   :Type: :zeek:type:`function` (p_one: :zeek:type:`opaque` of paraglob, p_two: :zeek:type:`opaque` of paraglob) : :zeek:type:`bool`

   Compares two paraglobs for equality.
   

   :param p_one: A compiled paraglob.
   

   :param p_two: A compiled paraglob.
   

   :returns: True if both paraglobs contain the same patterns, false otherwise.
   
   .. zeek:see:: paraglob_match paraglob_init

.. zeek:id:: paraglob_init
   :source-code: base/bif/zeek.bif.zeek 503 503

   :Type: :zeek:type:`function` (v: :zeek:type:`any`) : :zeek:type:`opaque` of paraglob

   Initializes and returns a new paraglob.
   

   :param v: Vector of patterns to initialize the paraglob with.
   

   :returns: A new, compiled, paraglob with the patterns in *v*
   
   .. zeek:see:: paraglob_match paraglob_equals

.. zeek:id:: paraglob_match
   :source-code: base/bif/zeek.bif.zeek 515 515

   :Type: :zeek:type:`function` (handle: :zeek:type:`opaque` of paraglob, match: :zeek:type:`string`) : :zeek:type:`string_vec`

   Gets all the patterns inside the handle associated with an input string.
   

   :param handle: A compiled paraglob.
   

   :param match: string to match against the paraglob.
   

   :returns: A vector of strings matching the input string.
   
   .. zeek:see:: paraglob_equals paraglob_init

.. zeek:id:: piped_exec
   :source-code: base/bif/zeek.bif.zeek 190 190

   :Type: :zeek:type:`function` (program: :zeek:type:`string`, to_write: :zeek:type:`string`) : :zeek:type:`bool`

   Opens a program with ``popen`` and writes a given string to the returned
   stream to send it to the opened process's stdin.
   

   :param program: The program to execute.
   

   :param to_write: Data to pipe to the opened program's process via ``stdin``.
   

   :returns: True on success.
   
   .. zeek:see:: system system_env

.. zeek:id:: port_to_count
   :source-code: base/bif/zeek.bif.zeek 1472 1472

   :Type: :zeek:type:`function` (p: :zeek:type:`port`) : :zeek:type:`count`

   Converts a :zeek:type:`port` to a :zeek:type:`count`.
   

   :param p: The :zeek:type:`port` to convert.
   

   :returns: The :zeek:type:`port` *p* as :zeek:type:`count`.
   
   .. zeek:see:: count_to_port

.. zeek:id:: pow
   :source-code: base/bif/zeek.bif.zeek 1041 1041

   :Type: :zeek:type:`function` (x: :zeek:type:`double`, y: :zeek:type:`double`) : :zeek:type:`double`

   Computes the *x* raised to the power *y*.
   

   :param x: The number to be raised to a power.
   

   :param y: The number that specifies a power.
   

   :returns: The number *x* raised to the power *y*.
   
   .. zeek:see:: floor ceil sqrt exp ln log2 log10

.. zeek:id:: preserve_prefix
   :source-code: base/bif/zeek.bif.zeek 2679 2679

   :Type: :zeek:type:`function` (a: :zeek:type:`addr`, width: :zeek:type:`count`) : :zeek:type:`any`

   Preserves the prefix of an IP address in anonymization.
   

   :param a: The address to preserve.
   

   :param width: The number of bits from the top that should remain intact.
   
   .. zeek:see:: preserve_subnet anonymize_addr
   
   .. todo:: Currently dysfunctional.

.. zeek:id:: preserve_subnet
   :source-code: base/bif/zeek.bif.zeek 2689 2689

   :Type: :zeek:type:`function` (a: :zeek:type:`subnet`) : :zeek:type:`any`

   Preserves the prefix of a subnet in anonymization.
   

   :param a: The subnet to preserve.
   
   .. zeek:see:: preserve_prefix anonymize_addr
   
   .. todo:: Currently dysfunctional.

.. zeek:id:: print_raw
   :source-code: base/bif/zeek.bif.zeek 949 949

   :Type: :zeek:type:`function` (...) : :zeek:type:`bool`

   Renders a sequence of values to a string of bytes and outputs them directly
   to ``stdout`` with no additional escape sequences added.  No additional
   newline is added to the end either.
   

   :returns: Always true.
   
   .. zeek:see:: fmt cat cat_sep string_cat to_json

.. zeek:id:: ptr_name_to_addr
   :source-code: base/bif/zeek.bif.zeek 1657 1657

   :Type: :zeek:type:`function` (s: :zeek:type:`string`) : :zeek:type:`addr`

   Converts a reverse pointer name to an address. For example,
   ``1.0.168.192.in-addr.arpa`` to ``192.168.0.1``.
   

   :param s: The string with the reverse pointer name.
   

   :returns: The IP address corresponding to *s*.
   
   .. zeek:see:: addr_to_ptr_name to_addr

.. zeek:id:: rand
   :source-code: base/bif/zeek.bif.zeek 580 580

   :Type: :zeek:type:`function` (max: :zeek:type:`count`) : :zeek:type:`count`

   Generates a random number.
   

   :param max: The maximum value of the random number.
   

   :returns: a random positive integer in the interval *[0, max)*.
   
   .. zeek:see:: srand
   
   .. note::
   
        This function is a wrapper about the function ``random``
        provided by the OS.

.. zeek:id:: raw_bytes_to_v4_addr
   :source-code: base/bif/zeek.bif.zeek 1587 1587

   :Type: :zeek:type:`function` (b: :zeek:type:`string`) : :zeek:type:`addr`

   Converts a :zeek:type:`string` of bytes into an IPv4 address. In particular,
   this function interprets the first 4 bytes of the string as an IPv4 address
   in network order.
   

   :param b: The raw bytes (:zeek:type:`string`) to convert.
   

   :returns: The byte :zeek:type:`string` *b* as :zeek:type:`addr`.
   
   .. zeek:see:: raw_bytes_to_v4_addr to_addr to_subnet

.. zeek:id:: raw_bytes_to_v6_addr
   :source-code: base/bif/zeek.bif.zeek 1599 1599

   :Type: :zeek:type:`function` (x: :zeek:type:`string`) : :zeek:type:`addr`

   Converts a :zeek:type:`string` of bytes into an IPv6 address. In particular,
   this function interprets the first 16 bytes of the string as an IPv6 address
   in network order.
   

   :param b: The raw bytes (:zeek:type:`string`) to convert.
   

   :returns: The byte :zeek:type:`string` *b* as :zeek:type:`addr`.
   
   .. zeek:see:: raw_bytes_to_v6_addr to_addr to_subnet

.. zeek:id:: reading_live_traffic
   :source-code: base/bif/zeek.bif.zeek 1129 1129

   :Type: :zeek:type:`function` () : :zeek:type:`bool`

   Checks whether Zeek reads traffic from one or more network interfaces (as
   opposed to from a network trace in a file). Note that this function returns
   true even after Zeek has stopped reading network traffic, for example due to
   receiving a termination signal.
   

   :returns: True if reading traffic from a network interface.
   
   .. zeek:see:: reading_traces packet_source

.. zeek:id:: reading_traces
   :source-code: base/bif/zeek.bif.zeek 1138 1138

   :Type: :zeek:type:`function` () : :zeek:type:`bool`

   Checks whether Zeek reads traffic from a trace file (as opposed to from a
   network interface).
   

   :returns: True if reading traffic from a network trace.
   
   .. zeek:see:: reading_live_traffic packet_source

.. zeek:id:: record_fields
   :source-code: base/bif/zeek.bif.zeek 1205 1205

   :Type: :zeek:type:`function` (rec: :zeek:type:`any`) : :zeek:type:`record_field_table`

   Generates metadata about a record's fields. The returned information
   includes the field name, whether it is logged, its value (if it has one),
   and its default value (if specified).
   

   :param rec: The record value or type to inspect.
   

   :returns: A table that describes the fields of a record. The returned table has
            the :zeek:attr:`&ordered` attribute set. Iterating over the table will
            yield entries for the fields in the same order as the fields were
            declared.

.. zeek:id:: remask_addr
   :source-code: base/bif/zeek.bif.zeek 1842 1842

   :Type: :zeek:type:`function` (a1: :zeek:type:`addr`, a2: :zeek:type:`addr`, top_bits_from_a1: :zeek:type:`count`) : :zeek:type:`addr`

   Takes some top bits (such as a subnet address) from one address and the other
   bits (intra-subnet part) from a second address and merges them to get a new
   address. This is useful for anonymizing at subnet level while preserving
   serial scans.
   

   :param a1: The address to mask with *top_bits_from_a1*.
   

   :param a2: The address to take the remaining bits from.
   

   :param top_bits_from_a1: The number of top bits to keep in *a1*; must be greater
                     than 0 and less than 129.  This value is always interpreted
                     relative to the IPv6 bit width (v4-mapped addresses start
                     at bit number 96).
   

   :returns: The address *a* masked down to *top_bits_to_keep* bits.
   
   .. zeek:see:: mask_addr

.. zeek:id:: rename
   :source-code: base/bif/zeek.bif.zeek 2326 2326

   :Type: :zeek:type:`function` (src_f: :zeek:type:`string`, dst_f: :zeek:type:`string`) : :zeek:type:`bool`

   Renames a file from src_f to dst_f.
   

   :param src_f: the name of the file to rename.
   

   :param dest_f: the name of the file after the rename operation.
   

   :returns: True if the rename succeeds and false otherwise.
   
   .. zeek:see:: active_file open_for_append close write_file
                get_file_name set_buf flush_all enable_raw_output
                mkdir rmdir unlink

.. zeek:id:: resize
   :source-code: base/bif/zeek.bif.zeek 812 812

   :Type: :zeek:type:`function` (aggr: :zeek:type:`any`, newsize: :zeek:type:`count`) : :zeek:type:`count`

   Resizes a vector.
   

   :param aggr: The vector instance.
   

   :param newsize: The new size of *aggr*.
   

   :returns: The old size of *aggr*, or 0 if *aggr* is not a :zeek:type:`vector`.

.. zeek:id:: rmdir
   :source-code: base/bif/zeek.bif.zeek 2299 2299

   :Type: :zeek:type:`function` (d: :zeek:type:`string`) : :zeek:type:`bool`

   Removes a directory.
   

   :param d: The directory name.
   

   :returns: True if the operation succeeds, and false if the
            directory delete operation fails.
   
   .. zeek:see:: active_file open_for_append close write_file
                get_file_name set_buf flush_all enable_raw_output
                mkdir unlink rename

.. zeek:id:: rotate_file
   :source-code: base/bif/zeek.bif.zeek 2357 2357

   :Type: :zeek:type:`function` (f: :zeek:type:`file`) : :zeek:type:`rotate_info`

   Rotates a file.
   

   :param f: An open file handle.
   

   :returns: Rotation statistics which include the original file name, the name
            after the rotation, and the time when *f* was opened/closed.
   
   .. zeek:see:: rotate_file_by_name calc_next_rotate

.. zeek:id:: rotate_file_by_name
   :source-code: base/bif/zeek.bif.zeek 2368 2368

   :Type: :zeek:type:`function` (f: :zeek:type:`string`) : :zeek:type:`rotate_info`

   Rotates a file identified by its name.
   

   :param f: The name of the file to rotate
   

   :returns: Rotation statistics which include the original file name, the name
            after the rotation, and the time when *f* was opened/closed.
   
   .. zeek:see:: rotate_file calc_next_rotate

.. zeek:id:: routing0_data_to_addrs
   :source-code: base/bif/zeek.bif.zeek 1315 1315

   :Type: :zeek:type:`function` (s: :zeek:type:`string`) : :zeek:type:`addr_vec`

   Converts the *data* field of :zeek:type:`ip6_routing` records that have
   *rtype* of 0 into a vector of addresses.
   

   :param s: The *data* field of an :zeek:type:`ip6_routing` record that has
      an *rtype* of 0.
   

   :returns: The vector of addresses contained in the routing header data.

.. zeek:id:: same_object
   :source-code: base/bif/zeek.bif.zeek 802 802

   :Type: :zeek:type:`function` (o1: :zeek:type:`any`, o2: :zeek:type:`any`) : :zeek:type:`bool`

   Checks whether two objects reference the same internal object. This function
   uses equality comparison of C++ raw pointer values to determine if the two
   objects are the same.
   

   :param o1: The first object.
   

   :param o2: The second object.
   

   :returns: True if *o1* and *o2* are equal.

.. zeek:id:: set_buf
   :source-code: base/bif/zeek.bif.zeek 2262 2262

   :Type: :zeek:type:`function` (f: :zeek:type:`file`, buffered: :zeek:type:`bool`) : :zeek:type:`any`

   Alters the buffering behavior of a file.
   

   :param f: A :zeek:type:`file` handle to an open file.
   

   :param buffered: When true, *f* is fully buffered, i.e., bytes are saved in a
             buffer until the block size has been reached. When
             false, *f* is line buffered, i.e., bytes are saved up until a
             newline occurs.
   
   .. zeek:see:: active_file open open_for_append close
                get_file_name write_file flush_all mkdir enable_raw_output
                rmdir unlink rename

.. zeek:id:: set_inactivity_timeout
   :source-code: base/bif/zeek.bif.zeek 2189 2189

   :Type: :zeek:type:`function` (cid: :zeek:type:`conn_id`, t: :zeek:type:`interval`) : :zeek:type:`interval`

   Sets an individual inactivity timeout for a connection and thus
   overrides the global inactivity timeout.
   

   :param cid: The connection ID.
   

   :param t: The new inactivity timeout for the connection identified by *cid*.
   

   :returns: The previous timeout interval.

.. zeek:id:: set_network_time
   :source-code: base/bif/zeek.bif.zeek 53 53

   :Type: :zeek:type:`function` (nt: :zeek:type:`time`) : :zeek:type:`bool`

   Sets the timestamp associated with the last packet processed. Used for
   event replaying.
   

   :param nt: The time to which to set "network time".
   

   :returns: The timestamp of the packet processed.
   
   .. zeek:see:: current_time network_time

.. zeek:id:: set_record_packets
   :source-code: base/bif/zeek.bif.zeek 2178 2178

   :Type: :zeek:type:`function` (cid: :zeek:type:`conn_id`, do_record: :zeek:type:`bool`) : :zeek:type:`bool`

   Controls whether packet contents belonging to a connection should be
   recorded (when ``-w`` option is provided on the command line).
   

   :param cid: The connection identifier.
   

   :param do_record: True to enable packet contents, and false to disable for the
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
   :source-code: base/bif/zeek.bif.zeek 122 122

   :Type: :zeek:type:`function` (var: :zeek:type:`string`, val: :zeek:type:`string`) : :zeek:type:`bool`

   Sets a system environment variable.
   

   :param var: The name of the variable.
   

   :param val: The (new) value of the variable *var*.
   

   :returns: True on success.
   
   .. zeek:see:: getenv

.. zeek:id:: sha1_hash
   :source-code: base/bif/zeek.bif.zeek 241 241

   :Type: :zeek:type:`function` (...) : :zeek:type:`string`

   Computes the SHA1 hash value of the provided list of arguments.
   

   :returns: The SHA1 hash value of the concatenated arguments.
   
   .. zeek:see:: md5_hash md5_hmac md5_hash_init md5_hash_update md5_hash_finish
      sha1_hash_init sha1_hash_update sha1_hash_finish
      sha256_hash sha256_hash_init sha256_hash_update sha256_hash_finish
      sha512_hash_init sha512_hash_update sha512_hash_finish
   
   .. note::
   
        This function performs a one-shot computation of its arguments.
        For incremental hash computation, see :zeek:id:`sha1_hash_init` and
        friends.

.. zeek:id:: sha1_hash_finish
   :source-code: base/bif/zeek.bif.zeek 467 467

   :Type: :zeek:type:`function` (handle: :zeek:type:`opaque` of sha1) : :zeek:type:`string`

   Returns the final SHA1 digest of an incremental hash computation.
   

   :param handle: The opaque handle associated with this hash computation.
   

   :returns: The hash value associated with the computation of *handle*.
   
   .. zeek:see:: md5_hmac md5_hash md5_hash_init md5_hash_update md5_hash_finish
      sha1_hash sha1_hash_init sha1_hash_update
      sha256_hash sha256_hash_init sha256_hash_update sha256_hash_finish
      sha512_hash sha512_hash_update sha512_hash_finish

.. zeek:id:: sha1_hash_init
   :source-code: base/bif/zeek.bif.zeek 330 330

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
   :source-code: base/bif/zeek.bif.zeek 407 407

   :Type: :zeek:type:`function` (handle: :zeek:type:`opaque` of sha1, data: :zeek:type:`string`) : :zeek:type:`bool`

   Updates the SHA1 value associated with a given index. It is required to
   call :zeek:id:`sha1_hash_init` once before calling this
   function.
   

   :param handle: The opaque handle associated with this hash computation.
   

   :param data: The data to add to the hash computation.
   

   :returns: True on success.
   
   .. zeek:see:: md5_hmac md5_hash md5_hash_init md5_hash_update md5_hash_finish
      sha1_hash sha1_hash_init sha1_hash_finish
      sha256_hash sha256_hash_init sha256_hash_update sha256_hash_finish
      sha512_hash sha512_hash_update sha512_hash_finish

.. zeek:id:: sha256_hash
   :source-code: base/bif/zeek.bif.zeek 258 258

   :Type: :zeek:type:`function` (...) : :zeek:type:`string`

   Computes the SHA256 hash value of the provided list of arguments.
   

   :returns: The SHA256 hash value of the concatenated arguments.
   
   .. zeek:see:: md5_hash md5_hmac md5_hash_init md5_hash_update md5_hash_finish
      sha1_hash sha1_hash_init sha1_hash_update sha1_hash_finish
      sha256_hash_init sha256_hash_update sha256_hash_finish
      sha512_hash_init sha512_hash_update sha512_hash_finish
   
   .. note::
   
        This function performs a one-shot computation of its arguments.
        For incremental hash computation, see :zeek:id:`sha256_hash_init` and
        friends.

.. zeek:id:: sha256_hash_finish
   :source-code: base/bif/zeek.bif.zeek 480 480

   :Type: :zeek:type:`function` (handle: :zeek:type:`opaque` of sha256) : :zeek:type:`string`

   Returns the final SHA256 digest of an incremental hash computation.
   

   :param handle: The opaque handle associated with this hash computation.
   

   :returns: The hash value associated with the computation of *handle*.
   
   .. zeek:see:: md5_hmac md5_hash md5_hash_init md5_hash_update md5_hash_finish
      sha1_hash sha1_hash_init sha1_hash_update sha1_hash_finish
      sha256_hash sha256_hash_init sha256_hash_update
      sha512_hash sha512_hash_update sha512_hash_finish

.. zeek:id:: sha256_hash_init
   :source-code: base/bif/zeek.bif.zeek 351 351

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
   :source-code: base/bif/zeek.bif.zeek 424 424

   :Type: :zeek:type:`function` (handle: :zeek:type:`opaque` of sha256, data: :zeek:type:`string`) : :zeek:type:`bool`

   Updates the SHA256 value associated with a given index. It is required to
   call :zeek:id:`sha256_hash_init` once before calling this
   function.
   

   :param handle: The opaque handle associated with this hash computation.
   

   :param data: The data to add to the hash computation.
   

   :returns: True on success.
   
   .. zeek:see:: md5_hmac md5_hash md5_hash_init md5_hash_update md5_hash_finish
      sha1_hash sha1_hash_init sha1_hash_update sha1_hash_finish
      sha256_hash sha256_hash_init sha256_hash_finish
      sha512_hash sha512_hash_update sha512_hash_finish

.. zeek:id:: sha512_hash
   :source-code: base/bif/zeek.bif.zeek 275 275

   :Type: :zeek:type:`function` (...) : :zeek:type:`string`

   Computes the SHA512 hash value of the provided list of arguments.
   

   :returns: The SHA512 hash value of the concatenated arguments.
   
   .. zeek:see:: md5_hash md5_hmac md5_hash_init md5_hash_update md5_hash_finish
      sha1_hash sha1_hash_init sha1_hash_update sha1_hash_finish
      sha256_hash_init sha256_hash_update sha256_hash_finish
      sha512_hash_init sha512_hash_update sha512_hash_finish
   
   .. note::
   
        This function performs a one-shot computation of its arguments.
        For incremental hash computation, see :zeek:id:`sha512_hash_init` and
        friends.

.. zeek:id:: sha512_hash_finish
   :source-code: base/bif/zeek.bif.zeek 493 493

   :Type: :zeek:type:`function` (handle: :zeek:type:`opaque` of sha512) : :zeek:type:`string`

   Returns the final SHA512 digest of an incremental hash computation.
   

   :param handle: The opaque handle associated with this hash computation.
   

   :returns: The hash value associated with the computation of *handle*.
   
   .. zeek:see:: md5_hmac md5_hash md5_hash_init md5_hash_update md5_hash_finish
      sha1_hash sha1_hash_init sha1_hash_update sha1_hash_finish
      sha256_hash sha256_hash_init sha256_hash_update
      sha512_hash sha512_hash_init sha512_hash_update

.. zeek:id:: sha512_hash_init
   :source-code: base/bif/zeek.bif.zeek 373 373

   :Type: :zeek:type:`function` () : :zeek:type:`opaque` of sha512

   Constructs an SHA512 handle to enable incremental hash computation. You can
   feed data to the returned opaque value with :zeek:id:`sha512_hash_update` and
   finally need to call :zeek:id:`sha512_hash_finish` to finish the computation
   and get the hash digest.
   
   For example, when computing incremental SHA512 values of transferred files in
   multiple concurrent HTTP connections, one keeps an optional handle in the
   HTTP session record. Then, one would call
   ``c$http$sha512_handle = sha512_hash_init()`` once before invoking
   ``sha512_hash_update(c$http$sha512_handle, some_more_data)`` in the
   :zeek:id:`http_entity_data` event handler. When all data has arrived, a call
   to :zeek:id:`sha512_hash_finish` returns the final hash value.
   

   :returns: The opaque handle associated with this hash computation.
   
   .. zeek:see:: md5_hmac md5_hash md5_hash_init md5_hash_update md5_hash_finish
      sha1_hash sha1_hash_init sha1_hash_update sha1_hash_finish
      sha256_hash sha256_hash_init sha256_hash_update
      sha512_hash sha512_hash_update sha512_hash_finish

.. zeek:id:: sha512_hash_update
   :source-code: base/bif/zeek.bif.zeek 441 441

   :Type: :zeek:type:`function` (handle: :zeek:type:`opaque` of sha512, data: :zeek:type:`string`) : :zeek:type:`bool`

   Updates the SHA512 value associated with a given index. It is required to
   call :zeek:id:`sha512_hash_init` once before calling this
   function.
   

   :param handle: The opaque handle associated with this hash computation.
   

   :param data: The data to add to the hash computation.
   

   :returns: True on success.
   
   .. zeek:see:: md5_hmac md5_hash md5_hash_init md5_hash_update md5_hash_finish
      sha1_hash sha1_hash_init sha1_hash_update sha1_hash_finish
      sha256_hash sha256_hash_init sha256_hash_update
      sha512_hash sha512_hash_init sha512_hash_finish

.. zeek:id:: skip_further_processing
   :source-code: base/bif/zeek.bif.zeek 2155 2155

   :Type: :zeek:type:`function` (cid: :zeek:type:`conn_id`) : :zeek:type:`bool`

   Informs Zeek that it should skip any further processing of the contents of
   a given connection. In particular, Zeek will refrain from reassembling the
   TCP byte stream and from generating events relating to any analyzers that
   have been processing the connection.
   

   :param cid: The connection ID.
   

   :returns: False if *cid* does not point to an active connection, and true
            otherwise.
   
   .. note::
   
       Zeek will still generate connection-oriented events such as
       :zeek:id:`connection_finished`.

.. zeek:id:: sleep
   :source-code: base/bif/zeek.bif.zeek 205 205

   :Type: :zeek:type:`function` (i: :zeek:type:`interval`) : :zeek:type:`interval`

   Sleeps for the given amount of time.
   

   :param i: The time interval to sleep for.
   

   :returns: The :zeek:type:`interval` Zeek actually slept for.
   
   .. note::
   
        This is a blocking sleep! Zeek will not run most of its processing
        during that time. You almost certainly DO NOT WANT THIS outside
        of specific testing/troubleshooting scenarios. To sleep asynchronously,
        :zeek:see:`schedule` an event, or consider :zeek:id:`Exec::run`.

.. zeek:id:: sort
   :source-code: base/bif/zeek.bif.zeek 854 854

   :Type: :zeek:type:`function` (...) : :zeek:type:`any`

   Sorts a vector in place. The second argument is a comparison function that
   takes two arguments: if the vector type is ``vector of T``, then the
   comparison function must be ``function(a: T, b: T): int``, which returns
   a value less than zero if ``a < b`` for some type-specific notion of the
   less-than operator.  The comparison function is optional if the type
   is a numeric type (int, count, double, time, etc.).
   

   :param v: The vector instance to sort.
   

   :returns: The vector, sorted from minimum to maximum value. If the vector
            could not be sorted, then the original vector is returned instead.
   
   .. zeek:see:: order

.. zeek:id:: sqrt
   :source-code: base/bif/zeek.bif.zeek 989 989

   :Type: :zeek:type:`function` (x: :zeek:type:`double`) : :zeek:type:`double`

   Computes the square root of a :zeek:type:`double`.
   

   :param x: The number to compute the square root of.
   

   :returns: The square root of *x*.
   
   .. zeek:see:: floor ceil exp ln log2 log10 pow

.. zeek:id:: srand
   :source-code: base/bif/zeek.bif.zeek 593 593

   :Type: :zeek:type:`function` (seed: :zeek:type:`count`) : :zeek:type:`any`

   Sets the seed for subsequent :zeek:id:`rand` calls.
   

   :param seed: The seed for the PRNG.
   
   .. zeek:see:: rand
   
   .. note::
   
        This function is a wrapper about the function ``srandom``
        provided by the OS.

.. zeek:id:: strftime
   :source-code: base/bif/zeek.bif.zeek 1789 1789

   :Type: :zeek:type:`function` (fmt: :zeek:type:`string`, d: :zeek:type:`time`) : :zeek:type:`string`

   Formats a given time value according to a format string.
   

   :param fmt: The format string. See ``man strftime`` for the syntax.
   

   :param d: The time value.
   

   :returns: The time *d* formatted according to *fmt*.

.. zeek:id:: string_to_pattern
   :source-code: base/bif/zeek.bif.zeek 1779 1779

   :Type: :zeek:type:`function` (s: :zeek:type:`string`, convert: :zeek:type:`bool`) : :zeek:type:`pattern`

   Converts a :zeek:type:`string` into a :zeek:type:`pattern`.
   

   :param s: The string to convert.
   

   :param convert: If true, *s* is first passed through the function
            :zeek:id:`convert_for_pattern` to escape special characters of
            patterns.
   

   :returns: *s* as :zeek:type:`pattern`.
   
   .. zeek:see:: convert_for_pattern

.. zeek:id:: strptime
   :source-code: base/bif/zeek.bif.zeek 1801 1801

   :Type: :zeek:type:`function` (fmt: :zeek:type:`string`, d: :zeek:type:`string`) : :zeek:type:`time`

   Parse a textual representation of a date/time value into a ``time`` type value.
   

   :param fmt: The format string used to parse the following *d* argument. See ``man strftime``
        for the syntax.
   

   :param d: The string representing the time.
   

   :returns: The time value calculated from parsing *d* with *fmt*.

.. zeek:id:: subnet_to_addr
   :source-code: base/bif/zeek.bif.zeek 1545 1545

   :Type: :zeek:type:`function` (sn: :zeek:type:`subnet`) : :zeek:type:`addr`

   Converts a :zeek:type:`subnet` to an :zeek:type:`addr` by
   extracting the prefix.
   

   :param sn: The subnet to convert.
   

   :returns: The subnet as an :zeek:type:`addr`.
   
   .. zeek:see:: to_subnet

.. zeek:id:: subnet_width
   :source-code: base/bif/zeek.bif.zeek 1555 1555

   :Type: :zeek:type:`function` (sn: :zeek:type:`subnet`) : :zeek:type:`count`

   Returns the width of a :zeek:type:`subnet`.
   

   :param sn: The subnet.
   

   :returns: The width of the subnet.
   
   .. zeek:see:: to_subnet

.. zeek:id:: suspend_processing
   :source-code: base/bif/zeek.bif.zeek 2604 2604

   :Type: :zeek:type:`function` () : :zeek:type:`any`

   Stops Zeek's packet processing. This function is used to synchronize
   distributed trace processing with communication enabled
   (*pseudo-realtime* mode).
   
   .. zeek:see:: continue_processing
                 is_processing_suspended

.. zeek:id:: syslog
   :source-code: base/bif/zeek.bif.zeek 601 601

   :Type: :zeek:type:`function` (s: :zeek:type:`string`) : :zeek:type:`any`

   Send a string to syslog.
   

   :param s: The string to log via syslog

.. zeek:id:: system
   :source-code: base/bif/zeek.bif.zeek 161 161

   :Type: :zeek:type:`function` (str: :zeek:type:`string`) : :zeek:type:`int`

   Invokes a command via the ``system`` function of the OS.
   The command runs in the background with ``stdout`` redirecting to
   ``stderr``. Here is a usage example:
   ``system(fmt("rm %s", safe_shell_quote(sniffed_data)));``
   

   :param str: The command to execute.
   

   :returns: The return value from the OS ``system`` function.
   
   .. zeek:see:: system_env safe_shell_quote piped_exec
   
   .. note::
   
        Note that this corresponds to the status of backgrounding the
        given command, not to the exit status of the command itself. A
        value of 127 corresponds to a failure to execute ``sh``, and -1
        to an internal system failure.

.. zeek:id:: system_env
   :source-code: base/bif/zeek.bif.zeek 177 177

   :Type: :zeek:type:`function` (str: :zeek:type:`string`, env: :zeek:type:`table_string_of_string`) : :zeek:type:`int`

   Invokes a command via the ``system`` function of the OS with a prepared
   environment. The function is essentially the same as :zeek:id:`system`,
   but changes the environment before invoking the command.
   

   :param str: The command to execute.
   

   :param env: A :zeek:type:`table` with the environment variables in the form
        of key-value pairs. Each specified environment variable name
        will be automatically prepended with ``ZEEK_ARG_``.
   

   :returns: The return value from the OS ``system`` function.
   
   .. zeek:see:: system safe_shell_quote piped_exec

.. zeek:id:: table_keys
   :source-code: base/bif/zeek.bif.zeek 757 757

   :Type: :zeek:type:`function` (t: :zeek:type:`any`) : :zeek:type:`any`

   Gets all keys from a table.
   

   :param t: The :zeek:type:`table`
   

   :returns: A ``set of T`` of all the keys in t.
   
   .. zeek:see:: table_values

.. zeek:id:: table_pattern_matcher_stats
   :source-code: base/bif/zeek.bif.zeek 2891 2891

   :Type: :zeek:type:`function` (tbl: :zeek:type:`any`) : :zeek:type:`MatcherStats`

   Return MatcherStats for a table[pattern] or set[pattern] value.
   
   This returns a MatcherStats objects that can be used for introspection
   of the DFA used for such a table. Statistics reset whenever elements are
   added or removed to the table as these operations result in the underlying
   DFA being rebuilt.
   
   This function iterates over all states of the DFA. Calling it at a high
   frequency is likely detrimental to performance.
   

   :param tbl: The table to get stats for.
   

   :returns: A record with matcher statistics.

.. zeek:id:: table_values
   :source-code: base/bif/zeek.bif.zeek 747 747

   :Type: :zeek:type:`function` (t: :zeek:type:`any`) : :zeek:type:`any_vec`

   Gets all values from a table.
   

   :param t: The :zeek:type:`table`
   

   :returns: A ``vector of T`` of all the values in t.
   
   .. zeek:see:: table_keys

.. zeek:id:: terminate
   :source-code: base/bif/zeek.bif.zeek 139 139

   :Type: :zeek:type:`function` () : :zeek:type:`bool`

   Gracefully shut down Zeek by terminating outstanding processing.
   

   :returns: True after successful termination and false when Zeek is still in
            the process of shutting down.
   
   .. zeek:see:: exit zeek_is_terminating

.. zeek:id:: time_to_double
   :source-code: base/bif/zeek.bif.zeek 1442 1442

   :Type: :zeek:type:`function` (t: :zeek:type:`time`) : :zeek:type:`double`

   Converts a :zeek:type:`time` value to a :zeek:type:`double`.
   

   :param t: The :zeek:type:`time` to convert.
   

   :returns: The :zeek:type:`time` value *t* as :zeek:type:`double`.
   
   .. zeek:see:: double_to_time

.. zeek:id:: to_addr
   :source-code: base/bif/zeek.bif.zeek 1496 1496

   :Type: :zeek:type:`function` (ip: :zeek:type:`string`) : :zeek:type:`addr`

   Converts a :zeek:type:`string` to an :zeek:type:`addr`.
   

   :param ip: The :zeek:type:`string` to convert.
   

   :returns: The :zeek:type:`string` *ip* as :zeek:type:`addr`, or the unspecified
            address ``::`` if the input string does not parse correctly.
   
   .. zeek:see:: to_count to_int to_port count_to_v4_addr raw_bytes_to_v4_addr raw_bytes_to_v6_addr
      to_subnet

.. zeek:id:: to_count
   :source-code: base/bif/zeek.bif.zeek 1402 1402

   :Type: :zeek:type:`function` (str: :zeek:type:`string`, base: :zeek:type:`count` :zeek:attr:`&default` = ``10`` :zeek:attr:`&optional`) : :zeek:type:`count`

   Converts a :zeek:type:`string` to a :zeek:type:`count`. For values where
   ``base`` is set to 16, a prefix of ``0x`` or ``0X`` will be ignored.
   

   :param str: The :zeek:type:`string` to convert.
   

   :param base: The :zeek:type:`count` to use as the numeric base.
   

   :returns: The :zeek:type:`string` *str* as unsigned integer, or 0 if *str* has
            an invalid format.
   
   .. zeek:see:: to_addr to_int to_port to_subnet

.. zeek:id:: to_double
   :source-code: base/bif/zeek.bif.zeek 1565 1565

   :Type: :zeek:type:`function` (str: :zeek:type:`string`) : :zeek:type:`double`

   Converts a :zeek:type:`string` to a :zeek:type:`double`.
   

   :param str: The :zeek:type:`string` to convert.
   

   :returns: The :zeek:type:`string` *str* as double, or 0 if *str* has
            an invalid format.
   

.. zeek:id:: to_int
   :source-code: base/bif/zeek.bif.zeek 1358 1358

   :Type: :zeek:type:`function` (str: :zeek:type:`string`, base: :zeek:type:`count` :zeek:attr:`&default` = ``10`` :zeek:attr:`&optional`) : :zeek:type:`int`

   Converts a :zeek:type:`string` to an :zeek:type:`int`. For values where
   ``base`` is set to 16, a prefix of ``0x`` or ``0X`` will be ignored.
   

   :param str: The :zeek:type:`string` to convert.
   

   :param base: The :zeek:type:`count` to use as the numeric base.
   

   :returns: The :zeek:type:`string` *str* as :zeek:type:`int`.
   
   .. zeek:see:: to_addr to_port to_subnet

.. zeek:id:: to_json
   :source-code: base/bif/zeek.bif.zeek 2731 2731

   :Type: :zeek:type:`function` (val: :zeek:type:`any`, only_loggable: :zeek:type:`bool` :zeek:attr:`&default` = ``F`` :zeek:attr:`&optional`, field_escape_pattern: :zeek:type:`pattern` :zeek:attr:`&default` = ``/^?(^_)$?/`` :zeek:attr:`&optional`, interval_as_double: :zeek:type:`bool` :zeek:attr:`&default` = ``F`` :zeek:attr:`&optional`) : :zeek:type:`string`

   A function to convert arbitrary Zeek data into a JSON string.
   

   :param v: The value to convert to JSON.  Typically a record.
   

   :param only_loggable: If the v value is a record this will only cause
                  fields with the &log attribute to be included in the JSON.
   

   :param field_escape_pattern: If the v value is a record, the given pattern is
                         matched against the field names of its type, and
                         the first match, if any, is stripped from the
                         rendered name. The default pattern strips a leading
                         underscore.
   

   :param interval_as_double: If T, interval values will be logged as doubles
                       instead of the broken-out version with units as strings.
   

   :param returns: a JSON formatted string.
   
   .. zeek:see:: fmt cat cat_sep string_cat print_raw from_json

.. zeek:id:: to_port
   :source-code: base/bif/zeek.bif.zeek 1609 1609

   :Type: :zeek:type:`function` (s: :zeek:type:`string`) : :zeek:type:`port`

   Converts a :zeek:type:`string` to a :zeek:type:`port`.
   

   :param s: The :zeek:type:`string` to convert.
   

   :returns: A :zeek:type:`port` converted from *s*.
   
   .. zeek:see:: to_addr to_count to_int to_subnet

.. zeek:id:: to_subnet
   :source-code: base/bif/zeek.bif.zeek 1524 1524

   :Type: :zeek:type:`function` (sn: :zeek:type:`string`) : :zeek:type:`subnet`

   Converts a :zeek:type:`string` to a :zeek:type:`subnet`.
   

   :param sn: The subnet to convert.
   

   :returns: The *sn* string as a :zeek:type:`subnet`, or the unspecified subnet
            ``::/0`` if the input string does not parse correctly.
   
   .. zeek:see:: to_count to_int to_port count_to_v4_addr raw_bytes_to_v4_addr raw_bytes_to_v6_addr
      to_addr

.. zeek:id:: type_aliases
   :source-code: base/bif/zeek.bif.zeek 1105 1105

   :Type: :zeek:type:`function` (x: :zeek:type:`any`) : :zeek:type:`string_set`

   Returns all type name aliases of a value or type.
   

   :param x: An arbitrary value or type.
   

   :returns: The set of all type name aliases of *x* (or the type of *x*
            if it's a value instead of a type).  For primitive values
            and types like :zeek:type:`string` or :zeek:type:`count`,
            this returns an empty set.  For types with user-defined
            names like :zeek:type:`record` or :zeek:type:`enum`, the
            returned set contains the original user-defined name for the
            type along with all aliases.  For other compound types, like
            :zeek:type:`table`, the returned set is empty unless
            explicitly requesting aliases for a user-defined type alias
            or a value that was explicitly created using a type alias
            (as opposed to originating from an "anonymous" constructor
            or initializer for that compound type).

.. zeek:id:: type_name
   :source-code: base/bif/zeek.bif.zeek 1084 1084

   :Type: :zeek:type:`function` (t: :zeek:type:`any`) : :zeek:type:`string`

   Returns the type name of an arbitrary Zeek variable.
   

   :param t: An arbitrary object.
   

   :returns: The type name of *t*.

.. zeek:id:: uninstall_dst_addr_filter
   :source-code: base/bif/zeek.bif.zeek 2570 2570

   :Type: :zeek:type:`function` (ip: :zeek:type:`addr`) : :zeek:type:`bool`

   Removes a destination address filter.
   

   :param ip: The IP address for which a destination filter was previously installed.
   

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
   :source-code: base/bif/zeek.bif.zeek 2589 2589

   :Type: :zeek:type:`function` (snet: :zeek:type:`subnet`) : :zeek:type:`bool`

   Removes a destination subnet filter.
   

   :param snet: The subnet for which a destination filter was previously installed.
   

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
   :source-code: base/bif/zeek.bif.zeek 2475 2475

   :Type: :zeek:type:`function` (ip: :zeek:type:`addr`) : :zeek:type:`bool`

   Removes a source address filter.
   

   :param ip: The IP address for which a source filter was previously installed.
   

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
   :source-code: base/bif/zeek.bif.zeek 2494 2494

   :Type: :zeek:type:`function` (snet: :zeek:type:`subnet`) : :zeek:type:`bool`

   Removes a source subnet filter.
   

   :param snet: The subnet for which a source filter was previously installed.
   

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
   :source-code: base/bif/zeek.bif.zeek 713 713

   :Type: :zeek:type:`function` (prefix: :zeek:type:`string`) : :zeek:type:`string`

   Creates an identifier that is unique with high probability.
   

   :param prefix: A custom string prepended to the result.
   

   :returns: A string identifier that is unique.
   
   .. zeek:see:: unique_id_from

.. zeek:id:: unique_id_from
   :source-code: base/bif/zeek.bif.zeek 725 725

   :Type: :zeek:type:`function` (pool: :zeek:type:`int`, prefix: :zeek:type:`string`) : :zeek:type:`string`

   Creates an identifier that is unique with high probability.
   

   :param pool: A seed for determinism.
   

   :param prefix: A custom string prepended to the result.
   

   :returns: A string identifier that is unique.
   
   .. zeek:see:: unique_id

.. zeek:id:: unlink
   :source-code: base/bif/zeek.bif.zeek 2312 2312

   :Type: :zeek:type:`function` (f: :zeek:type:`string`) : :zeek:type:`bool`

   Removes a file from a directory.
   

   :param f: the file to delete.
   

   :returns: True if the operation succeeds and the file was deleted,
            and false if the deletion fails.
   
   .. zeek:see:: active_file open_for_append close write_file
                get_file_name set_buf flush_all enable_raw_output
                mkdir rmdir rename

.. zeek:id:: uuid_to_string
   :source-code: base/bif/zeek.bif.zeek 1749 1749

   :Type: :zeek:type:`function` (uuid: :zeek:type:`string`) : :zeek:type:`string`

   Converts a bytes representation of a UUID into its string form. For example,
   given a string of 16 bytes, it produces an output string in this format:
   ``550e8400-e29b-41d4-a716-446655440000``.
   See `<http://en.wikipedia.org/wiki/Universally_unique_identifier>`_.
   

   :param uuid: The 16 bytes of the UUID.
   

   :returns: The string representation of *uuid*.

.. zeek:id:: val_footprint
   :source-code: base/bif/zeek.bif.zeek 1166 1166

   :Type: :zeek:type:`function` (v: :zeek:type:`any`) : :zeek:type:`count`

   Computes a value's "footprint": the number of objects the value contains
   either directly or indirectly.  The number is not meant to be precise, but
   rather comparable: larger footprint correlates with more memory consumption.
   

   :returns: the footprint.
   
   .. zeek:see:: global_container_footprints

.. zeek:id:: write_file
   :source-code: base/bif/zeek.bif.zeek 2247 2247

   :Type: :zeek:type:`function` (f: :zeek:type:`file`, data: :zeek:type:`string`) : :zeek:type:`bool`

   Writes data to an open file.
   

   :param f: A :zeek:type:`file` handle to an open file.
   

   :param data: The data to write to *f*.
   

   :returns: True on success.
   
   .. zeek:see:: active_file open open_for_append close
                get_file_name set_buf flush_all mkdir enable_raw_output
                rmdir unlink rename

.. zeek:id:: zeek_args
   :source-code: base/bif/zeek.bif.zeek 1118 1118

   :Type: :zeek:type:`function` () : :zeek:type:`string_vec`


   :returns: list of command-line arguments (``argv``) used to run Zeek.

.. zeek:id:: zeek_is_terminating
   :source-code: base/bif/zeek.bif.zeek 1251 1251

   :Type: :zeek:type:`function` () : :zeek:type:`bool`

   Checks if Zeek is terminating.
   

   :returns: True if Zeek is in the process of shutting down.
   
   .. zeek:see:: terminate

.. zeek:id:: zeek_version
   :source-code: base/bif/zeek.bif.zeek 1068 1068

   :Type: :zeek:type:`function` () : :zeek:type:`string`

   Returns the Zeek version string.
   

   :returns: Zeek's version, e.g., 2.0-beta-47-debug.


