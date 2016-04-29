
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

Before building Bro, you need to install libGeoIP.

* FreeBSD:

  .. console::

      sudo pkg install GeoIP

* RPM/RedHat-based Linux:

  .. console::

      sudo yum install GeoIP-devel

* DEB/Debian-based Linux:

  .. console::

      sudo apt-get install libgeoip-dev

* Mac OS X:

  You need to install from your preferred package management system
  (e.g. MacPorts, Fink, or Homebrew).  The name of the package that you need
  may be libgeoip, geoip, or geoip-dev, depending on which package management
  system you are using.


GeoIPLite Database Installation
-------------------------------

A country database for GeoIPLite is included when you do the C API
install, but for Bro, we are using the city database which includes
cities and regions in addition to countries.

`Download <http://www.maxmind.com/app/geolitecity>`__ the GeoLite city
binary database:

.. console::

    wget http://geolite.maxmind.com/download/geoip/database/GeoLiteCity.dat.gz
    gunzip GeoLiteCity.dat.gz

Next, the file needs to be renamed and put in the GeoIP database directory.
This directory should already exist and will vary depending on which platform
and package you are using.  For FreeBSD, use ``/usr/local/share/GeoIP``.  For
Linux, use ``/usr/share/GeoIP`` or ``/var/lib/GeoIP`` (choose whichever one
already exists).
    
.. console::

    mv GeoLiteCity.dat <path_to_database_dir>/GeoIPCity.dat

Note that there is a separate database for IPv6 addresses, which can also
be installed if you want GeoIP functionality for IPv6.

Testing
-------

Before using the GeoIP functionality, it is a good idea to verify that
everything is setup correctly.  After installing libGeoIP and the GeoIP city
database, and building Bro, you can quickly check if the GeoIP functionality
works by running a command like this:

.. console::

    bro -e "print lookup_location(8.8.8.8);"

If you see an error message similar to "Failed to open GeoIP City database",
then you may need to either rename or move your GeoIP city database file (the
error message should give you the full pathname of the database file that
Bro is looking for).

If you see an error message similar to "Bro was not configured for GeoIP
support", then you need to rebuild Bro and make sure it is linked against
libGeoIP.  Normally, if libGeoIP is installed correctly then it should
automatically be found when building Bro.  If this doesn't happen, then
you may need to specify the path to the libGeoIP installation
(e.g. ``./configure --with-geoip=<path>``).

Usage
-----

There is a built-in function that provides the GeoIP functionality:

.. code:: bro

    function lookup_location(a:addr): geo_location

The return value of the :bro:see:`lookup_location` function is a record
type called :bro:see:`geo_location`, and it consists of several fields
containing the country, region, city, latitude, and longitude of the specified
IP address.  Since one or more fields in this record will be uninitialized
for some IP addresses (for example, the country and region of an IP address
might be known, but the city could be unknown), a field should be checked
if it has a value before trying to access the value.

Example
-------

To show every ftp connection from hosts in Ohio, this is now very easy:

.. code:: bro

    event ftp_reply(c: connection, code: count, msg: string, cont_resp: bool)
    {
      local client = c$id$orig_h;
      local loc = lookup_location(client);

      if (loc?$region && loc$region == "OH" && loc$country_code == "US")
      {
        local city = loc?$city ? loc$city : "<unknown>";

        print fmt("FTP Connection from:%s (%s,%s,%s)", client, city,
          loc$region, loc$country_code);
      }
    }

