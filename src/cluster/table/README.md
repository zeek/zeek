This directory contains plugin providing low-level BiF function that can be
used as &on_change function to disseminate table state among Zeek nodes.


To debug this functionality, enable its debug stream that is automatically
installed by the plugin infrastructure:

    ZEEK_DEBUG_LOG_STREAMS=plugin-Zeek-Cluster_Table ZEEK_DEBUG_LOG_STDERR=1 btest -d cluster/table
