##! An implementation of highest random weight (HRW) hashing, also called
##! rendezvous hashing. See
##! `<https://en.wikipedia.org/wiki/Rendezvous_hashing>`_.

module HashHRW;

export {
	## A site/node is a unique location to which you want a subset of keys
	## to be distributed.
	type Site: record {
		## A unique identifier for the site, should not exceed what
		## can be contained in a 32-bit integer.
		id: count;
		## Other data to associate with the site.
		user_data: any &optional;
	};

	## A table of sites, indexed by their id.
	type SiteTable: table[count] of Site;

	## A collection of sites to distribute keys across.
	type Pool: record {
		sites: SiteTable &default=SiteTable();
	};

	## Add a site to a pool.
	##
	## Returns: F is the site is already in the pool, else T.
	global add_site: function(pool: Pool, site: Site): bool;

	## Remove a site from a pool.
	##
	## Returns: F if the site is not in the pool, else T.
	global rem_site: function(pool: Pool, site: Site): bool;

	## Returns: the site to which the key maps.
	global get_site: function(pool: Pool, key: any): Site;
}

function add_site(pool: Pool, site: Site): bool
	{
	if ( site$id in pool$sites )
		return F;

	pool$sites[site$id] = site;
	return T;
	}

function rem_site(pool: Pool, site: Site): bool
	{
	if ( site$id !in pool$sites )
		return F;

	delete pool$sites[site$id];
	return T;
	}

function get_site(pool: Pool, key: any): Site
	{
    local best_site_id = 0;
    local best_weight = -1;
    local d = fnv1a32(key);

    for ( site_id in pool$sites )
        {
        local w = hrw_weight(d, site_id);

        if ( w > best_weight || (w == best_weight && site_id > best_site_id) )
            {
            best_weight = w;
            best_site_id = site_id;
            }
        }

    return pool$sites[best_site_id];
	}
