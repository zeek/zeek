@load policy/protocols/ssh/interesting-hostnames.bro

hook Notice::policy(n: Notice::Info)
  {
  if ( n$note == SSH::Interesting_Hostname_Login )
      add n$actions[Notice::ACTION_EMAIL];
  }
