
.. _geolocation:

===========
GeoLocation
===========

.. rst-class:: opening

    During the process of creating policy scripts the need may arise
    to find the geographic location for an IP address. Bro had support
    for the `GeoIP library <http://www.maxmind.com/app/c>`__ at the
    policy script level from release 1.3 to 2.5.x to account for this
    need.  Starting with release 2.6, GeoIP support requires `libmaxminddb
    <https://github.com/maxmind/libmaxminddb/releases>`__.
    To use this functionality, you need to first install the libmaxminddb
    software, and then install the GeoLite2 city database before building
    Bro.

.. contents::

Install libmaxminddb
--------------------

Before building Bro, you need to install libmaxminddb.

* RPM/RedHat-based Linux:

  .. console::

      sudo yum install libmaxminddb-devel

* DEB/Debian-based Linux:

  .. console::

      sudo apt-get install libmaxminddb-dev

* FreeBSD:

  .. console::

      sudo pkg install libmaxminddb

* Mac OS X:

  You need to install from your preferred package management system
  (e.g. Homebrew, MacPorts, or Fink).  For Homebrew, the name of the package
  that you need is libmaxminddb.


GeoLite2-City Database Installation
-----------------------------------

Bro can use the city or country database.  The city database includes cities
and regions in addition to countries.

`Download <http://geolite.maxmind.com/download/geoip/database/GeoLite2-City.tar.gz>`__
the GeoLite2 city binary database:

.. console::

    wget http://geolite.maxmind.com/download/geoip/database/GeoLite2-City.tar.gz
    tar zxf GeoLite2-City.tar.gz

Next, the file "GeoLite2-City_YYYYMMDD/GeoLite2-City.mmdb" needs to be moved
to the GeoIP database directory.  This directory might already exist
and will vary depending on which platform and package you are using.  For
FreeBSD, use ``/usr/local/share/GeoIP``.  For Linux, use ``/usr/share/GeoIP``
or ``/var/lib/GeoIP`` (choose whichever one already exists).
    
.. console::

    mv <extracted subdir>/GeoLite2-City.mmdb <path_to_database_dir>/GeoLite2-City.mmdb

Testing
-------

Before using the GeoIP functionality, it is a good idea to verify that
everything is setup correctly.  After installing libmaxminddb and the GeoIP
city database, and building Bro, you can quickly check if the GeoIP
functionality works by running a command like this:

.. console::

    bro -e "print lookup_location(8.8.8.8);"

If you see an error message similar to "Failed to open GeoIP location
database", then you may need to either rename or move your GeoIP
location database file.  If the :bro:see:`mmdb_dir` value is set to a
directory pathname (it is not set by default), then Bro looks for location
database files in that directory.  If none are found or if mmdb_dir is not set,
then Bro looks for location database files in the following order:

* /usr/share/GeoIP/GeoLite2-City.mmdb
* /var/lib/GeoIP/GeoLite2-City.mmdb
* /usr/local/share/GeoIP/GeoLite2-City.mmdb
* /usr/local/var/GeoIP/GeoLite2-City.mmdb
* /usr/share/GeoIP/GeoLite2-Country.mmdb
* /var/lib/GeoIP/GeoLite2-Country.mmdb
* /usr/local/share/GeoIP/GeoLite2-Country.mmdb
* /usr/local/var/GeoIP/GeoLite2-Country.mmdb

If you see an error message similar to "Bro was not configured for GeoIP
support", then you need to rebuild Bro and make sure it is linked
against libmaxminddb.  Normally, if libmaxminddb is installed correctly then it
should automatically be found when building Bro.  If this doesn't
happen, then you may need to specify the path to the libmaxminddb
installation (e.g. ``./configure --with-geoip=<path>``).

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

