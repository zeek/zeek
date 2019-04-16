@load policy/protocols/ssl/expiring-certs.zeek

hook Notice::policy(n: Notice::Info) 
   {
   if ( n$note == SSL::Certificate_Expires_Soon )
       n$suppress_for = 12hrs;
   }
