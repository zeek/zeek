signature dpd_ssh {
  ip-proto == tcp
  payload /^[sS][sS][hH]-[12]./
  enable "ssh"
}

