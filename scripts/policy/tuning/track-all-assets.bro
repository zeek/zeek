@load base/frameworks/software
@load protocols/conn/known-hosts
@load protocols/conn/known-services
@load protocols/ssl/known-certs

redef Software::asset_tracking      = ALL_HOSTS;
redef KnownHosts::asset_tracking    = ALL_HOSTS;
redef KnownServices::asset_tracking = ALL_HOSTS;
redef KnownCerts::asset_tracking    = ALL_HOSTS;
