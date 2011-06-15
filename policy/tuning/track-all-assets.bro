
@load software
@load conn/known-hosts
@load conn/known-services

redef Software::asset_tracking      = ALL_HOSTS;
redef KnownHosts::asset_tracking    = ALL_HOSTS;
redef KnownServices::asset_tracking = ALL_HOSTS;