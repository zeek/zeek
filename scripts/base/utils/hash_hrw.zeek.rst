:tocdepth: 3

base/utils/hash_hrw.zeek
========================
.. zeek:namespace:: HashHRW

An implementation of highest random weight (HRW) hashing, also called
rendezvous hashing. See
`<https://en.wikipedia.org/wiki/Rendezvous_hashing>`_.

:Namespace: HashHRW

Summary
~~~~~~~
Types
#####
=================================================== ===================================================================
:zeek:type:`HashHRW::Pool`: :zeek:type:`record`     A collection of sites to distribute keys across.
:zeek:type:`HashHRW::Site`: :zeek:type:`record`     A site/node is a unique location to which you want a subset of keys
                                                    to be distributed.
:zeek:type:`HashHRW::SiteTable`: :zeek:type:`table` A table of sites, indexed by their id.
=================================================== ===================================================================

Functions
#########
=================================================== ========================================
:zeek:id:`HashHRW::add_site`: :zeek:type:`function` Add a site to a pool.
:zeek:id:`HashHRW::get_site`: :zeek:type:`function` Returns: the site to which the key maps.
:zeek:id:`HashHRW::rem_site`: :zeek:type:`function` Remove a site from a pool.
=================================================== ========================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Types
#####
.. zeek:type:: HashHRW::Pool

   :Type: :zeek:type:`record`

      sites: :zeek:type:`HashHRW::SiteTable` :zeek:attr:`&default` = ``{  }`` :zeek:attr:`&optional`

   A collection of sites to distribute keys across.

.. zeek:type:: HashHRW::Site

   :Type: :zeek:type:`record`

      id: :zeek:type:`count`
         A unique identifier for the site, should not exceed what
         can be contained in a 32-bit integer.

      user_data: :zeek:type:`any` :zeek:attr:`&optional`
         Other data to associate with the site.

   A site/node is a unique location to which you want a subset of keys
   to be distributed.

.. zeek:type:: HashHRW::SiteTable

   :Type: :zeek:type:`table` [:zeek:type:`count`] of :zeek:type:`HashHRW::Site`

   A table of sites, indexed by their id.

Functions
#########
.. zeek:id:: HashHRW::add_site

   :Type: :zeek:type:`function` (pool: :zeek:type:`HashHRW::Pool`, site: :zeek:type:`HashHRW::Site`) : :zeek:type:`bool`

   Add a site to a pool.
   

   :returns: F is the site is already in the pool, else T.

.. zeek:id:: HashHRW::get_site

   :Type: :zeek:type:`function` (pool: :zeek:type:`HashHRW::Pool`, key: :zeek:type:`any`) : :zeek:type:`HashHRW::Site`


   :returns: the site to which the key maps.

.. zeek:id:: HashHRW::rem_site

   :Type: :zeek:type:`function` (pool: :zeek:type:`HashHRW::Pool`, site: :zeek:type:`HashHRW::Site`) : :zeek:type:`bool`

   Remove a site from a pool.
   

   :returns: F if the site is not in the pool, else T.


