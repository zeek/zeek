@load http-summary

redef HTTP_summary::log = open_log_file("ipp-summary") &redef;
