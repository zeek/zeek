<h1 align="center">

[![Zeek Logo](https://zeek.org/wp-content/uploads/2020/04/zeek-logo-without-text.png)](https://www.zeek.org)

 Zeek fork with TCP Urgent Pointer and IP Reserved Bit

</h1><h4 align="center">

A ***complicated*** framework for network traffic analysis and security monitoring.

[_Key Features_](#key-features) —
[_Getting Started_](#getting-started) —
[_Development_](#development) —
[_License_](#license)

</h4>


Key Features
--------------
* This Zeek fork adds the TCP Urgent Pointer to the header, as well as the Reserved Bit field to the IPv4 header

Getting Started
---------------

The best place to find information about getting started with Zeek is [www.zeek.org](https://www.zeek.org), specifically the sparse
[documentation](https://www.zeek.org/documentation/index.html) section. On the web site you can also find tutorials on getting Zeek set up. Unfortunatly, not a lot of code examples or well written documentation is available for Zeek. 

Clone the master git repository:

`git clone --recursive https://github.com/Schmittenberger/ZEEK-TCP-Urgent-Pointer-fork`

Install all [dependencies](https://docs.zeek.org/en/stable/install/install.html#prerequisites) locally.
Then build and install:

`./configure && make && sudo make install`

(this may take a while)

Development
-----------
This Zeek fork wont receive any updates after my thesis. Feel free though to take my changes and incorporate them in your own build.


License
-------

Zeek comes with a BSD license, allowing for free use with virtually no
restrictions. You can find it [here](https://github.com/zeek/zeek/blob/master/COPYING).
