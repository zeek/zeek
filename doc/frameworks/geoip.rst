
.. _geolocation:

===========
GeoLocation
===========

.. rst-class:: opening

    During the process of creating policy scripts the need may arise
    to find the geographic location for an IP address. Bro has support
    for the `GeoIP library <http://www.maxmind.com/app/c>`__ at the
    policy script level beginning with release 1.3 to account for this
    need.  To use this functionality, you need to first install the libGeoIP
    software, and then install the GeoLite city database before building
    Bro.

.. contents::

Install libGeoIP
----------------

* FreeBSD:

  .. console::

      sudo pkg_add -r GeoIP

* RPM/RedHat-based Linux:

  .. console::

      sudo yum install GeoIP-devel

* DEB/Debian-based Linux:

  .. console::

      sudo apt-get install libgeoip-dev

* Mac OS X:

  Vanilla OS X installations don't ship with libGeoIP, but if
  installed from your preferred package management system (e.g.
  MacPorts, Fink, or Homebrew), they should be automatically detected
  and Bro will compile against them.


GeoIPLite Database Installation
------------------------------------

A country database for GeoIPLite is included when you do the C API
install, but for Bro, we are using the city database which includes
cities and regions in addition to countries.

`Download <http://www.maxmind.com/app/geolitecity>`__ the GeoLite city
binary database.

  .. console::

    wget http://geolite.maxmind.com/download/geoip/database/GeoLiteCity.dat.gz
    gunzip GeoLiteCity.dat.gz

Next, the file needs to be put in the database directory.  This directory
should already exist and will vary depending on which platform and package
you are using.  For FreeBSD, use ``/usr/local/share/GeoIP``.  For Linux,
use ``/usr/share/GeoIP`` or ``/var/lib/GeoIP`` (choose whichever one
already exists).
    
  .. console::

    mv GeoLiteCity.dat <path_to_database_dir>/GeoIPCity.dat


Usage
-----

There is a single built in function that provides the GeoIP
functionality:

.. code:: bro

    function lookup_location(a:addr): geo_location

There is also the :bro:see:`geo_location` data structure that is returned
from the :bro:see:`lookup_location` function:

.. code:: bro

    type geo_location: record {
      country_code: string;
      region: string;
      city: string;
      latitude: double;
      longitude: double;
    };


Example
-------

To write a line in a log file for every ftp connection from hosts in
Ohio, this is now very easy:

.. code:: bro

    global ftp_location_log: file = open_log_file("ftp-location");
    
    event ftp_reply(c: connection, code: count, msg: string, cont_resp: bool)
    {
      local client = c$id$orig_h;
      local loc = lookup_location(client);
      if (loc$region == "OH" && loc$country_code == "US")
      {
        print ftp_location_log, fmt("FTP Connection from:%s (%s,%s,%s)", client, loc$city, loc$region, loc$country_code); 
      }
    }


