<h1 align="center">

[![Zeek Logo](https://www.zeek.org/images/bro-eyes.png)](https:://www.zeek.org)

The Zeek Network Security Monitor

</h1><h4 align="center">

A [powerful](https://www.zeek.org/why_choose_zeek.pdf) framework for network analysis and security monitoring

[_Key Features_](#key-features) - 
[_Documentation_](https://docs.zeek.org/en/stable/index.html) - 
[_Getting Started_](#getting-started) - 
[_Development_](#development) - 
[_License_](#license)

</h4>

## Key Features

* <b>Adaptable and Flexible</b>
	Zeek's domain-specific scripting language enables site-specific monitoring policies and means that it is not restricted to any particular detection approach.

* <b>In-depth Analysis</b>
	Zeek comes with analyzers for many protocols, enabling high-level semantic analysis at the application layer.
	
* <b>Efficient</b>
	Zeek targets high-performance networks and is used operationally at a variety of large sites.

* <b>Highly Stateful</b>
	Zeek keeps extensive application-layer state about the network it monitors and provides a high-level archive of a network's activity.

## Getting Started
The best place to find information about getting started with Zeek is our [website](https://www.zeek.org/documentation/index.html). You can find downloads for stable releases, tutorials on getting Zeek set up, and many other useful resources there. You can also find release notes for the current version and a complete history of changes in [NEWS](https://github.com/zeek/zeek/blob/master/NEWS), and [CHANGES](https://github.com/zeek/zeek/blob/master/CHANGES) respectively.

To work on the development branch of Zeek, clone the master git repository. 

`git clone --recursive https://github.com/zeek/zeek `

With its [dependencies](https://docs.zeek.org/en/stable/install/install.html#prerequisites) installed, build and install.

`./configure && make && sudo make install`

Write your first Zeek script.
```zeek
// hello.zeek

event zeek_init
  {
  print "Hello World!";
  }
```
And run it.

`zeek hello.zeek`



## Development
Zeek is developed on GitHub by its community. Today, as a result countless contributions, it is is used operationally around the world by major companies and educational and scientific institutions alike for securing their cyber infrastructure. We welcome contributions. Working on an open source project like Zeek can be an incredibly rewarding experience and, packet by packet, makes the internet a little safer.

If you're interested in getting involved, we actively collect feature requests and issues on GitHub [here](https://github.com/zeek/zeek/issues) and you might find [these](https://github.com/zeek/zeek/issues?q=is%3Aissue+is%3Aopen+label%3A%22Difficulty%3A+Easy%22) to be a good place to get started. For learning more about the Zeek scripting language, try.zeek.org is a great place to get started.


More information on Zeek's development can be found [here](https://www.zeek.org/development/index.html), and information about its community and mailing lists (which are fairly active) can be found [here](https://www.zeek.org/community/index.html).

## License
Zeek comes with a BSD license, allowing for free use with virtually no restrictions. You can read it [here](https://github.com/zeek/zeek/blob/master/COPYING).
