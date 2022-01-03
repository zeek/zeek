# @TEST-DOC: Basic functionality test for Bittorrent Tracker analyzer.

# @TEST-EXEC: zeek -C -b -r $TRACES/bittorrent/tracker.pcap -s bittorrent.sig %INPUT >output
# @TEST-EXEC: btest-diff output

# Zeek doesn't ship with scripts or DPD sigs for Bittorrent, so we need to provide what
# we need ourselves.

event bt_tracker_request(c: connection, uri: string, headers: bt_tracker_headers) {
    print c$id, uri, headers;
}

@TEST-START-FILE bittorrent.sig

# Reusing the old Bro 1.5 signatures here.

signature dpd_bittorrenttracker_client {
  ip-proto == tcp
  payload /^.*\/announce\?.*info_hash/
  tcp-state originator
}

signature dpd_bittorrenttracker_server {
  ip-proto == tcp
  payload /^HTTP\/[0-9]/
  tcp-state responder
  requires-reverse-signature dpd_bittorrenttracker_client
  enable "bittorrenttracker"
}

signature dpd_bittorrent_peer1 {
  ip-proto == tcp
  payload /^\x13BitTorrent protocol/
  tcp-state originator
}

signature dpd_bittorrent_peer2 {
  ip-proto == tcp
  payload /^\x13BitTorrent protocol/
  tcp-state responder
  requires-reverse-signature dpd_bittorrent_peer1
  enable "bittorrent"
}

@TEST-END-FILE
