# Only load if the shunter plugin provided the necessary BiFs
@ifdef ( XDP::__load_and_attach )
@load ./main
@load ./connect
@load ./shunt-conn-id
@load ./conn-id-logging
@load ./shunt-ip-pair

@load ./bulk
@load ./ssl
@endif
