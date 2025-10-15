:tocdepth: 3

base/protocols/ldap/consts.zeek
===============================
.. zeek:namespace:: LDAP


:Namespace: LDAP

Summary
~~~~~~~
Redefinable Options
###################
================================================================================================================ =
:zeek:id:`LDAP::EXTENDED_REQUESTS`: :zeek:type:`table` :zeek:attr:`&default` = ``"unknown"`` :zeek:attr:`&redef` 
================================================================================================================ =

Constants
#########
=============================================================================================== =
:zeek:id:`LDAP::BIND_SASL`: :zeek:type:`string`                                                 
:zeek:id:`LDAP::BIND_SICILY_NEGOTIATE`: :zeek:type:`string`                                     
:zeek:id:`LDAP::BIND_SICILY_RESPONSE`: :zeek:type:`string`                                      
:zeek:id:`LDAP::BIND_SIMPLE`: :zeek:type:`string`                                               
:zeek:id:`LDAP::PROTOCOL_OPCODES`: :zeek:type:`table` :zeek:attr:`&default` = ``"unknown"``     
:zeek:id:`LDAP::RESULT_CODES`: :zeek:type:`table` :zeek:attr:`&default` = ``"unknown"``         
:zeek:id:`LDAP::SEARCH_DEREF_ALIASES`: :zeek:type:`table` :zeek:attr:`&default` = ``"unknown"`` 
:zeek:id:`LDAP::SEARCH_SCOPES`: :zeek:type:`table` :zeek:attr:`&default` = ``"unknown"``        
=============================================================================================== =


Detailed Interface
~~~~~~~~~~~~~~~~~~
Redefinable Options
###################
.. zeek:id:: LDAP::EXTENDED_REQUESTS
   :source-code: base/protocols/ldap/consts.zeek 126 126

   :Type: :zeek:type:`table` [:zeek:type:`string`] of :zeek:type:`string`
   :Attributes: :zeek:attr:`&default` = ``"unknown"`` :zeek:attr:`&redef`
   :Default:

      ::

         {
            ["1.3.6.1.4.1.1466.20037"] = "StartTLS",
            ["1.3.6.1.4.1.4203.1.11.3"] = "whoami"
         }



Constants
#########
.. zeek:id:: LDAP::BIND_SASL
   :source-code: base/protocols/ldap/consts.zeek 28 28

   :Type: :zeek:type:`string`
   :Default: ``"bind SASL"``


.. zeek:id:: LDAP::BIND_SICILY_NEGOTIATE
   :source-code: base/protocols/ldap/consts.zeek 29 29

   :Type: :zeek:type:`string`
   :Default: ``"sicily_negotiate"``


.. zeek:id:: LDAP::BIND_SICILY_RESPONSE
   :source-code: base/protocols/ldap/consts.zeek 30 30

   :Type: :zeek:type:`string`
   :Default: ``"sicily_response"``


.. zeek:id:: LDAP::BIND_SIMPLE
   :source-code: base/protocols/ldap/consts.zeek 27 27

   :Type: :zeek:type:`string`
   :Default: ``"bind simple"``


.. zeek:id:: LDAP::PROTOCOL_OPCODES
   :source-code: base/protocols/ldap/consts.zeek 4 4

   :Type: :zeek:type:`table` [:zeek:type:`LDAP::ProtocolOpcode`] of :zeek:type:`string`
   :Attributes: :zeek:attr:`&default` = ``"unknown"``
   :Default:

      ::

         {
            [LDAP::ProtocolOpcode_SEARCH_RESULT_REFERENCE] = "search",
            [LDAP::ProtocolOpcode_UNBIND_REQUEST] = "unbind",
            [LDAP::ProtocolOpcode_INTERMEDIATE_RESPONSE] = "intermediate",
            [LDAP::ProtocolOpcode_COMPARE_REQUEST] = "compare",
            [LDAP::ProtocolOpcode_COMPARE_RESPONSE] = "compare",
            [LDAP::ProtocolOpcode_MODIFY_REQUEST] = "modify",
            [LDAP::ProtocolOpcode_ABANDON_REQUEST] = "abandon",
            [LDAP::ProtocolOpcode_EXTENDED_RESPONSE] = "extended",
            [LDAP::ProtocolOpcode_ADD_REQUEST] = "add",
            [LDAP::ProtocolOpcode_EXTENDED_REQUEST] = "extended",
            [LDAP::ProtocolOpcode_ADD_RESPONSE] = "add",
            [LDAP::ProtocolOpcode_BIND_RESPONSE] = "bind",
            [LDAP::ProtocolOpcode_DEL_RESPONSE] = "delete",
            [LDAP::ProtocolOpcode_MODIFY_RESPONSE] = "modify",
            [LDAP::ProtocolOpcode_SEARCH_RESULT_DONE] = "search",
            [LDAP::ProtocolOpcode_DEL_REQUEST] = "delete",
            [LDAP::ProtocolOpcode_SEARCH_RESULT_ENTRY] = "search",
            [LDAP::ProtocolOpcode_MOD_DN_RESPONSE] = "modify",
            [LDAP::ProtocolOpcode_MOD_DN_REQUEST] = "modify",
            [LDAP::ProtocolOpcode_SEARCH_REQUEST] = "search",
            [LDAP::ProtocolOpcode_BIND_REQUEST] = "bind"
         }



.. zeek:id:: LDAP::RESULT_CODES
   :source-code: base/protocols/ldap/consts.zeek 32 32

   :Type: :zeek:type:`table` [:zeek:type:`LDAP::ResultCode`] of :zeek:type:`string`
   :Attributes: :zeek:attr:`&default` = ``"unknown"``
   :Default:

      ::

         {
            [LDAP::ResultCode_NO_RESULTS_RETURNED] = "no results returned",
            [LDAP::ResultCode_CONSTRAINT_VIOLATION] = "constraint violation",
            [LDAP::ResultCode_ATTRIBUTE_OR_VALUE_EXISTS] = "attribute or value exists",
            [LDAP::ResultCode_ALIAS_PROBLEM] = "alias problem",
            [LDAP::ResultCode_CLIENT_LOOP] = "client loop",
            [LDAP::ResultCode_NOT_ALLOWED_ON_RDN] = "not allowed on RDN",
            [LDAP::ResultCode_NAMING_VIOLATION] = "naming violation",
            [LDAP::ResultCode_CONNECT_ERROR] = "connect error",
            [LDAP::ResultCode_PARTIAL_RESULTS] = "partial results",
            [LDAP::ResultCode_ENTRY_ALREADY_EXISTS] = "entry already exists",
            [LDAP::ResultCode_REFERRAL_LIMIT_EXCEEDED] = "referral limit exceeded",
            [LDAP::ResultCode_UNWILLING_TO_PERFORM] = "unwilling to perform",
            [LDAP::ResultCode_AFFECTS_MULTIPLE_DSAS] = "affects multiple DSAs",
            [LDAP::ResultCode_UNAVAILABLE] = "unavailable",
            [LDAP::ResultCode_INVALID_ATTRIBUTE_SYNTAX] = "invalid attribute syntax",
            [LDAP::ResultCode_SIZE_LIMIT_EXCEEDED] = "size limit exceeded",
            [LDAP::ResultCode_UNAVAILABLE_CRITICAL_EXTENSION] = "unavailable critical extension",
            [LDAP::ResultCode_UNDEFINED_ATTRIBUTE_TYPE] = "undefined attribute type",
            [LDAP::ResultCode_NO_SUCH_OPERATION] = "no such operation",
            [LDAP::ResultCode_OTHER] = "other",
            [LDAP::ResultCode_SERVER_DOWN] = "server down",
            [LDAP::ResultCode_USER_CANCELED] = "user canceled",
            [LDAP::ResultCode_CONTROL_ERROR] = "control error",
            [LDAP::ResultCode_NO_SUCH_ATTRIBUTE] = "no such attribute",
            [LDAP::ResultCode_LCUP_INVALID_DATA] = "LCUP invalid data",
            [LDAP::ResultCode_LOOP_DETECT] = "loop detect",
            [LDAP::ResultCode_MORE_RESULTS_TO_RETURN] = "more results to return",
            [LDAP::ResultCode_NO_MEMORY] = "no memory",
            [LDAP::ResultCode_OPERATIONS_ERROR] = "operations error",
            [LDAP::ResultCode_AUTH_UNKNOWN] = "auth unknown",
            [LDAP::ResultCode_LCUP_UNSUPPORTED_SCHEME] = "LCUP unsupported scheme",
            [LDAP::ResultCode_ADMIN_LIMIT_EXCEEDED] = "admin limit exceeded",
            [LDAP::ResultCode_INTERMEDIATE_RESPONSE] = "intermediate response",
            [LDAP::ResultCode_TIME_LIMIT_EXCEEDED] = "time limit exceeded",
            [LDAP::ResultCode_UNKNOWN_TYPE] = "unknown type",
            [LDAP::ResultCode_INVALID_DNSYNTAX] = "invalid DN syntax",
            [LDAP::ResultCode_ALIAS_DEREFERENCING_PROBLEM] = "alias dereferencing problem",
            [LDAP::ResultCode_COMPARE_TRUE] = "compare true",
            [LDAP::ResultCode_SASL_BIND_IN_PROGRESS] = "SASL bind in progress",
            [LDAP::ResultCode_STRONGER_AUTH_REQUIRED] = "stronger auth required",
            [LDAP::ResultCode_ENCODING_ERROR] = "encoding error",
            [LDAP::ResultCode_LOCAL_ERROR] = "local error",
            [LDAP::ResultCode_ASSERTION_FAILED] = "assertion failed",
            [LDAP::ResultCode_AUTH_METHOD_NOT_SUPPORTED] = "auth method not supported",
            [LDAP::ResultCode_NOT_ALLOWED_ON_NON_LEAF] = "not allowed on non-leaf",
            [LDAP::ResultCode_NOT_SUPPORTED] = "not supported",
            [LDAP::ResultCode_REFERRAL] = "referral",
            [LDAP::ResultCode_OBJECT_CLASS_VIOLATION] = "object class violation",
            [LDAP::ResultCode_NO_SUCH_OBJECT] = "no such object",
            [LDAP::ResultCode_CONFIDENTIALITY_REQUIRED] = "confidentiality required",
            [LDAP::ResultCode_AMBIGUOUS_RESPONSE] = "ambiguous response",
            [LDAP::ResultCode_PARAM_ERROR] = "param error",
            [LDAP::ResultCode_CANCELED] = "canceled",
            [LDAP::ResultCode_RESULTS_TOO_LARGE] = "results too large",
            [LDAP::ResultCode_CONTROL_NOT_FOUND] = "control not found",
            [LDAP::ResultCode_INSUFFICIENT_ACCESS_RIGHTS] = "insufficient access rights",
            [LDAP::ResultCode_TOO_LATE] = "too late",
            [LDAP::ResultCode_PROTOCOL_ERROR] = "protocol error",
            [LDAP::ResultCode_CANNOT_CANCEL] = "cannot cancel",
            [LDAP::ResultCode_INAPPROPRIATE_AUTHENTICATION] = "inappropriate authentication",
            [LDAP::ResultCode_OBJECT_CLASS_MODS_PROHIBITED] = "object class mods prohibited",
            [LDAP::ResultCode_TIMEOUT] = "timeout",
            [LDAP::ResultCode_INVALID_CREDENTIALS] = "invalid credentials",
            [LDAP::ResultCode_COMPARE_FALSE] = "compare false",
            [LDAP::ResultCode_TLS_NOT_SUPPORTED] = "TLS not supported",
            [LDAP::ResultCode_OFFSET_RANGE_ERROR] = "offset range error",
            [LDAP::ResultCode_SORT_CONTROL_MISSING] = "sort control missing",
            [LDAP::ResultCode_INVALID_RESPONSE] = "invalid response",
            [LDAP::ResultCode_BUSY] = "busy",
            [LDAP::ResultCode_INAPPROPRIATE_MATCHING] = "inappropriate matching",
            [LDAP::ResultCode_LCUP_RELOAD_REQUIRED] = "LCUP reload required",
            [LDAP::ResultCode_SUCCESS] = "success",
            [LDAP::ResultCode_AUTHORIZATION_DENIED] = "authorization denied",
            [LDAP::ResultCode_FILTER_ERROR] = "filter error",
            [LDAP::ResultCode_DECODING_ERROR] = "decoding error"
         }



.. zeek:id:: LDAP::SEARCH_DEREF_ALIASES
   :source-code: base/protocols/ldap/consts.zeek 120 120

   :Type: :zeek:type:`table` [:zeek:type:`LDAP::SearchDerefAlias`] of :zeek:type:`string`
   :Attributes: :zeek:attr:`&default` = ``"unknown"``
   :Default:

      ::

         {
            [LDAP::SearchDerefAlias_DEREF_NEVER] = "never",
            [LDAP::SearchDerefAlias_DEREF_FINDING_BASE] = "finding",
            [LDAP::SearchDerefAlias_DEREF_ALWAYS] = "always",
            [LDAP::SearchDerefAlias_DEREF_IN_SEARCHING] = "searching"
         }



.. zeek:id:: LDAP::SEARCH_SCOPES
   :source-code: base/protocols/ldap/consts.zeek 116 116

   :Type: :zeek:type:`table` [:zeek:type:`LDAP::SearchScope`] of :zeek:type:`string`
   :Attributes: :zeek:attr:`&default` = ``"unknown"``
   :Default:

      ::

         {
            [LDAP::SearchScope_SEARCH_BASE] = "base",
            [LDAP::SearchScope_SEARCH_TREE] = "tree",
            [LDAP::SearchScope_SEARCH_SINGLE] = "single"
         }




