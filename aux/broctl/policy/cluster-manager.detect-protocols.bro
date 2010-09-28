# $Id: cluster-manager.detect-protocols.bro 6811 2009-07-06 20:41:10Z robin $

redef FilterDuplicates::filters += {
    [ServerFound] = FilterDuplicates::match_src_port
};

