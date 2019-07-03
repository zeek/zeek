<h1 align="center">
  <br>
<a href="https://www.zeek.org">
  <img src="https://www.zeek.org/images/bro-eyes.png" alt="The Zeek Logo" />
  </a>
  <br><br>
  The Zeek Network Security Monitor
  <br>
</h1>
<h4 align="center">A <a href ="https://www.zeek.org/why_choose_zeek.pdf">powerful</a> framework for network analysis and security monitoring.</h4>
<p align="center">
  <a href="#key-features">Key Features</a> -
  <a href="https://docs.zeek.org/en/stable/index.html">Documentation</a> -
  <a href="#getting-started">Getting Started</a> -
  <a href="#development">Development</a> -
  <a href="#license">License</a>
</p>

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
The best place to find information about getting started with Zeek is our [website](https://www.zeek.org/documentation/index.html). You can find downloads for stable relases, tutorials on getting Zeek set up, and many other useful resources there. You can also find release notes for the current version in [NEWS](https://github.com/zeek/zeek/blob/master/NEWS), and [CHANGES](https://github.com/zeek/zeek/blob/master/CHANGES) has the complete history of changes

To work on the development branch of Zeek, clone the master git repository. 

`git clone --recursive https://github.com/zeek/zeek `

Then, with its [dependencies](https://docs.zeek.org/en/stable/install/install.html#prerequisites) installed, build and install.

`./configure && make && sudo make install`


## Development
Zeek was originally developed by Vern Paxson. Robin Sommer now leads the project, jointly with a core team of researchers and developers at the [International Computer Science Institute](http://www.icsi.berkeley.edu) in Berkeley, CA; and the [National Center for Supercomputing Applications](http://www.ncsa.illinois.edu) in Urbana-Champaign, IL.

Zeek is developed on GitHub and we welcome contributions. Working on an open-source project like Zeek can be an incredibly rewarding experience. We actively collect feature requests and issues on GitHub [here](https://github.com/zeek/zeek/issues). If you're looking for a good first issue you might find [these](https://github.com/zeek/zeek/issues?q=is%3Aissue+is%3Aopen+label%3A%22Difficulty%3A+Easy%22) useful.

More information on Zeek's development can be found [here](https://www.zeek.org/development/index.html), and information about its community and mailing lists (which are fairly active) can be found [here](https://www.zeek.org/community/index.html).  

## License
Zeek comes with a BSD license, allowing for free use with virtually no restrictions. You can read it [here](https://github.com/zeek/zeek/blob/master/COPYING).
