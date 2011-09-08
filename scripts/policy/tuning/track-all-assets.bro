@load base/frameworks/software
@load protocols/conn/known-hosts
@load protocols/conn/known-services
@load protocols/ssl/known-certs

redef Software::asset_tracking  = ALL_HOSTS;
redef Known::host_tracking      = ALL_HOSTS;
redef Known::service_tracking   = ALL_HOSTS;
redef Known::cert_tracking      = ALL_HOSTS;
