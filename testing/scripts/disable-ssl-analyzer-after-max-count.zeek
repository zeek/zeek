@load base/protocols/ssl
module SSL;

global ssl_encrypted_data_count: count = 0;
global ssl_encrypted_data_max_count: count = 2;

event ssl_encrypted_data(c: connection, is_client: bool, record_version: count, content_type: count, length: count)
    {
    ++ssl_encrypted_data_count;

    if ( c$ssl?$analyzer_id &&
         ssl_encrypted_data_count >= ssl_encrypted_data_max_count )
        disable_analyzer(c$id, c$ssl$analyzer_id);
    }
