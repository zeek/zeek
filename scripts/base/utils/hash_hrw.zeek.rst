:tocdepth: 3

base/utils/hash_hrw.zeek
========================
.. bro:namespace:: HashHRW

An implementation of highest random weight (HRW) hashing, also called
rendezvous hashing. See
`<https://en.wikipedia.org/wiki/Rendezvous_hashing>`_.

:Namespace: HashHRW

Summary
~~~~~~~
Types
#####
================================================= ===================================================================
:bro:type:`HashHRW::Pool`: :bro:type:`record`     A collection of sites to distribute keys across.
:bro:type:`HashHRW::Site`: :bro:type:`record`     A site/node is a unique location to which you want a subset of keys
                                                  to be distributed.
:bro:type:`HashHRW::SiteTable`: :bro:type:`table` A table of sites, indexed by their id.
================================================= ===================================================================

Functions
#########
================================================= ========================================
:bro:id:`HashHRW::add_site`: :bro:type:`function` Add a site to a pool.
:bro:id:`HashHRW::get_site`: :bro:type:`function` Returns: the site to which the key maps.
:bro:id:`HashHRW::rem_site`: :bro:type:`function` Remove a site from a pool.
================================================= ========================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Types
#####
.. bro:type:: HashHRW::Pool

   :Type: :bro:type:`record`

      sites: :bro:type:`HashHRW::SiteTable` :bro:attr:`&default` = ``{  }`` :bro:attr:`&optional`

   A collection of sites to distribute keys across.

.. bro:type:: HashHRW::Site

   :Type: :bro:type:`record`

      id: :bro:type:`count`
         A unique identifier for the site, should not exceed what
         can be contained in a 32-bit integer.

      user_data: :bro:type:`any` :bro:attr:`&optional`
         Other data to associate with the site.

   A site/node is a unique location to which you want a subset of keys
   to be distributed.

.. bro:type:: HashHRW::SiteTable

   :Type: :bro:type:`table` [:bro:type:`count`] of :bro:type:`HashHRW::Site`

   A table of sites, indexed by their id.

Functions
#########
.. bro:id:: HashHRW::add_site

   :Type: :bro:type:`function` (pool: :bro:type:`HashHRW::Pool`, site: :bro:type:`HashHRW::Site`) : :bro:type:`bool`

   Add a site to a pool.
   

   :returns: F is the site is already in the pool, else T.

.. bro:id:: HashHRW::get_site

   :Type: :bro:type:`function` (pool: :bro:type:`HashHRW::Pool`, key: :bro:type:`any`) : :bro:type:`HashHRW::Site`


   :returns: the site to which the key maps.

.. bro:id:: HashHRW::rem_site

   :Type: :bro:type:`function` (pool: :bro:type:`HashHRW::Pool`, site: :bro:type:`HashHRW::Site`) : :bro:type:`bool`

   Remove a site from a pool.
   

   :returns: F if the site is not in the pool, else T.


