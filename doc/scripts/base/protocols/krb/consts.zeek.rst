:tocdepth: 3

base/protocols/krb/consts.zeek
==============================
.. zeek:namespace:: KRB


:Namespace: KRB

Summary
~~~~~~~
Constants
#########
============================================================================================= =
:zeek:id:`KRB::cipher_name`: :zeek:type:`table` :zeek:attr:`&default` = :zeek:type:`function` 
:zeek:id:`KRB::error_msg`: :zeek:type:`table` :zeek:attr:`&default` = :zeek:type:`function`   
============================================================================================= =


Detailed Interface
~~~~~~~~~~~~~~~~~~
Constants
#########
.. zeek:id:: KRB::cipher_name
   :source-code: base/protocols/krb/consts.zeek 76 76

   :Type: :zeek:type:`table` [:zeek:type:`count`] of :zeek:type:`string`
   :Attributes: :zeek:attr:`&default` = :zeek:type:`function`
   :Default:

      ::

         {
            [2] = "des-cbc-md4",
            [25] = "camellia128-cts-cmac",
            [14] = "rsaES-OAEP-ENV-OID",
            [15] = "des-ede3-cbc-Env-OID",
            [16] = "des3-cbc-sha1-kd",
            [24] = "rc4-hmac-exp",
            [23] = "rc4-hmac",
            [9] = "dsaWithSHA1-CmsOID",
            [1] = "des-cbc-crc",
            [11] = "sha1WithRSAEncryption-CmsOID",
            [7] = "des3-cbc-sha1",
            [5] = "des3-cbc-md5",
            [10] = "md5WithRSAEncryption-CmsOID",
            [13] = "rsaEncryption-EnvOID",
            [12] = "rc2CBC-EnvOID",
            [26] = "camellia256-cts-cmac",
            [65] = "subkey-keymaterial",
            [18] = "aes256-cts-hmac-sha1-96",
            [3] = "des-cbc-md5",
            [17] = "aes128-cts-hmac-sha1-96"
         }



.. zeek:id:: KRB::error_msg
   :source-code: base/protocols/krb/consts.zeek 5 5

   :Type: :zeek:type:`table` [:zeek:type:`count`] of :zeek:type:`string`
   :Attributes: :zeek:attr:`&default` = :zeek:type:`function`
   :Default:

      ::

         {
            [19] = "KDC_ERR_SERVICE_REVOKED",
            [20] = "KDC_ERR_TGT_REVOKED",
            [33] = "KRB_AP_ERR_TKT_NYV",
            [39] = "KRB_AP_ERR_BADVERSION",
            [67] = "KRB_AP_ERR_NO_TGT",
            [73] = "KDC_ERR_REVOCATION_STATUS_UNKNOWN",
            [75] = "KDC_ERR_CLIENT_NAME_MISMATCH",
            [46] = "KRB_AP_ERR_MUT_FAIL",
            [15] = "KDC_ERR_SUMTYPE_NOSUPP",
            [64] = "KDC_ERROR_INVALID_SIG",
            [28] = "KDC_ERR_PATH_NOT_ACCEPTED",
            [9] = "KDC_ERR_NULL_KEY",
            [68] = "KDC_ERR_WRONG_REALM",
            [71] = "KDC_ERR_INVALID_CERTIFICATE",
            [52] = "KRB_ERR_RESPONSE_TOO_BIG",
            [21] = "KDC_ERR_CLIENT_NOTYET",
            [4] = "KDC_ERR_C_OLD_MAST_KVNO",
            [12] = "KDC_ERR_POLICY",
            [41] = "KRB_AP_ERR_MODIFIED",
            [17] = "KDC_ERR_TRTYPE_NOSUPP",
            [25] = "KDC_ERR_PREAUTH_REQUIRED",
            [76] = "KDC_ERR_KDC_NAME_MISMATCH",
            [29] = "KDC_ERR_SVC_UNAVAILABLE",
            [16] = "KDC_ERR_PADATA_TYPE_NOSUPP",
            [38] = "KRB_AP_ERR_BADADDR",
            [63] = "KDC_ERROR_KDC_NOT_TRUSTED",
            [42] = "KRB_AP_ERR_BADORDER",
            [1] = "KDC_ERR_NAME_EXP",
            [11] = "KDC_ERR_NEVER_VALID",
            [35] = "KRB_AP_ERR_NOT_US",
            [22] = "KDC_ERR_SERVICE_NOTYET",
            [3] = "KDC_ERR_BAD_PVNO",
            [44] = "KRB_AP_ERR_BADKEYVER",
            [34] = "KRB_AP_ERR_REPEAT",
            [45] = "KRB_AP_ERR_NOKEY",
            [40] = "KRB_AP_ERR_MSG_TYPE",
            [36] = "KRB_AP_ERR_BADMATCH",
            [14] = "KDC_ERR_ETYPE_NOSUPP",
            [6] = "KDC_ERR_C_PRINCIPAL_UNKNOWN",
            [31] = "KRB_AP_ERR_BAD_INTEGRITY",
            [8] = "KDC_ERR_PRINCIPAL_NOT_UNIQUE",
            [23] = "KDC_ERR_KEY_EXPIRED",
            [27] = "KDC_ERR_MUST_USE_USER2USER",
            [7] = "KDC_ERR_S_PRINCIPAL_UNKNOWN",
            [66] = "KDC_ERR_CERTIFICATE_MISMATCH",
            [10] = "KDC_ERR_CANNOT_POSTDATE",
            [32] = "KRB_AP_ERR_TKT_EXPIRED",
            [13] = "KDC_ERR_BADOPTION",
            [26] = "KDC_ERR_SERVER_NOMATCH",
            [65] = "KDC_ERR_KEY_TOO_WEAK",
            [62] = "KDC_ERROR_CLIENT_NOT_TRUSTED",
            [74] = "KDC_ERR_REVOCATION_STATUS_UNAVAILABLE",
            [47] = "KRB_AP_ERR_BADDIRECTION",
            [70] = "KDC_ERR_CANT_VERIFY_CERTIFICATE",
            [50] = "KRB_AP_ERR_INAPP_CKSUM",
            [2] = "KDC_ERR_SERVICE_EXP",
            [72] = "KDC_ERR_REVOKED_CERTIFICATE",
            [48] = "KRB_AP_ERR_METHOD",
            [24] = "KDC_ERR_PREAUTH_FAILED",
            [69] = "KRB_AP_ERR_USER_TO_USER_REQUIRED",
            [49] = "KRB_AP_ERR_BADSEQ",
            [5] = "KDC_ERR_S_OLD_MAST_KVNO",
            [61] = "KRB_ERR_FIELD_TOOLONG",
            [60] = "KRB_ERR_GENERIC",
            [51] = "KRB_AP_PATH_NOT_ACCEPTED",
            [37] = "KRB_AP_ERR_SKEW",
            [18] = "KDC_ERR_CLIENT_REVOKED",
            [0] = "KDC_ERR_NONE"
         }




