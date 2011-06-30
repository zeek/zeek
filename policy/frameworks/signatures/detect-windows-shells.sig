signature windows_reverse_shell {
  ip-proto == tcp
  tcp-state established,originator
  event "ATTACK-RESPONSES Microsoft cmd.exe banner (reverse-shell originator)"
  payload /.*Microsoft Windows.*\x28C\x29 Copyright 1985-.*Microsoft Corp/
}

signature windows_shell {
  ip-proto == tcp
  tcp-state established,responder
  event "ATTACK-RESPONSES Microsoft cmd.exe banner (normal-shell responder)"
  payload /.*Microsoft Windows.*\x28C\x29 Copyright 1985-.*Microsoft Corp/
}
