signature dpd_rdp_client_request {
  ip-proto == tcp
  payload /.*Cookie: mstshash\=.*/	
  enable "rdp"
}

signature dpd_rdp_client_header {
  ip-proto == tcp
  payload /.*Duca.*(rdpdr|rdpsnd|drdynvc|cliprdr).*/
  enable "rdp"
}

signature dpd_rdp_server_response {
  ip-proto == tcp
  payload /.*McDn.*/
  enable "rdp"
}
