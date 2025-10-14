@load base/frameworks/config

@load ja3
@load zeek-community-id
@load zeek-community-id/notice

redef Config::config_files += { "./myconfig.dat" };

module Packages;

export {
    # All packages off by default.
    option community_id_enabled = F;
    option ja3_enabled = F;
}

event zeek_init()
    {
    local package_change_handler = function(id: string, new_value: bool): bool {
        local modules: set[string];

        if ( id == "Packages::community_id_enabled" )
            modules = ["CommunityID", "CommunityID::Notice"];
        else if ( id == "Packages::ja3_enabled" )
            modules = ["JA3", "JA3_Server"];
        else
            {
            Reporter::error(fmt("Unknown option: %s", id));
            return new_value;
            }

        # Toggle the modules.
        for ( m in modules )
            if ( new_value )
                enable_module_events(m);
            else
                disable_module_events(m);

        return new_value;
    };

    Option::set_change_handler("Packages::community_id_enabled", package_change_handler);
    Option::set_change_handler("Packages::ja3_enabled", package_change_handler);

    Config::set_value("Packages::community_id_enabled", F);
    Config::set_value("Packages::ja3_enabled", F);
    }
