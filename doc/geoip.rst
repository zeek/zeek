
===========
GeoLocation
===========

.. rst-class:: opening

    During the process of creating policy scripts the need may arise
    to find the geographic location for an IP address. Bro has support
    for the `GeoIP library <http://www.maxmind.com/app/c>`__ at the
    policy script level beginning with release 1.3 to account for this
    need.

.. contents::

GeoIPLite Database Installation
------------------------------------

A country database for GeoIPLite is included when you do the C API
install, but for Bro, we are using the city database which includes
cities and regions in addition to countries.

`Download <http://www.maxmind.com/app/geolitecity>`__ the geolitecity
binary database and follow the directions to install it.

FreeBSD Quick Install
---------------------

.. console::

    pkg_add -r GeoIP
    wget http://geolite.maxmind.com/download/geoip/database/GeoLiteCity.dat.gz
    gunzip GeoLiteCity.dat.gz
    mv GeoLiteCity.dat /usr/local/share/GeoIP/GeoIPCity.dat
    
    # Set your environment correctly before running Bro's configure script
    export CFLAGS=-I/usr/local/include
    export LDFLAGS=-L/usr/local/lib


CentOS Quick Install
--------------------

.. console::

    yum install GeoIP-devel
    
    wget http://geolite.maxmind.com/download/geoip/database/GeoLiteCity.dat.gz
    gunzip GeoLiteCity.dat.gz
    mkdir -p /var/lib/GeoIP/
    mv GeoLiteCity.dat /var/lib/GeoIP/GeoIPCity.dat
    
    # Set your environment correctly before running Bro's configure script
    export CFLAGS=-I/usr/local/include
    export LDFLAGS=-L/usr/local/lib


Usage
-----

There is a single built in function that provides the GeoIP
functionality:

.. code:: bro

    function lookup_location(a:addr): geo_location

There is also the ``geo_location`` data structure that is returned
from the ``lookup_location`` function:

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


