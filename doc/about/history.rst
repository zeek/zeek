History
=======

Zeek has a rich history stretching back to the 1990s. Vern Paxson
designed and implemented the initial version in 1995 as a researcher at the
`Lawrence Berkeley National Laboratory (LBNL) <https://www.lbl.gov/>`_.
The original software was called “Bro,” as an “Orwellian reminder that
monitoring comes hand in hand with the potential for privacy violations”.

LBNL first deployed Zeek in 1996, and the USENIX Security Symposium published
Vern’s original paper on Zeek in 1998, and awarded it the Best Paper Award that
year He published a refined version of the paper in 1999 as `Bro: A System for
Detecting Network Intruders in Real-Time
<https://www.usenix.org/legacy/publications/library/proceedings/sec98/full_papers/paxson/paxson.pdf>`_.

In 2003, the `National Science Foundation (NSF) <https://www.nsf.gov/>`_ began
supporting research and advanced development on Bro at the `International
Computer Science Institute (ICSI) <https://www.icsi.berkeley.edu/>`_.

Over the years, a growing team of ICSI researchers and students kept adding
novel functions to Zeek, while LBNL continued its support with funding from the
`Department of Energy (DOE) <https://www.energy.gov/>`_. Much of Zeek’s
capabilities originate in academic research projects, with results often
published at top-tier conferences. A key to Zeek’s success was the project’s
ability to bridge the gap between academia and operations. This relationship
helped ground research on Zeek in real-world challenges.

With a growing operational user community, the research-centric development
model eventually became a bottleneck to the system’s evolution.  Research
grants did not support the more mundane parts of software development and
maintenance. However, those elements were crucial for the end-user experience.
As a result, deploying Zeek required overcoming a steep learning curve.

In 2010, NSF sought to address this challenge by awarding ICSI a grant from its
Software Development for Cyberinfrastructure fund. The `National Center for
Supercomputing Applications (NCSA) <https://ncsa.illinois.edu/>`_ joined the
team as a core partner, and the Zeek project began to overhaul many of the
user-visible parts of the system for the 2.0 release in 2012.

After Zeek 2.0, the project enjoyed tremendous growth in new deployments across
a diverse range of settings, and the ongoing collaboration between ICSI (co-PI
Robin Sommer) and NCSA (co-PI Adam Slagell) brought a number of important
features.  In 2012, Zeek added native IPv6 support, long before many enterprise
networking monitoring tools. In 2013, NSF renewed its support with a second
grant that established the Bro Center of Expertise at ICSI and NCSA, promoting
Zeek as a comprehensive, low-cost security capability for research and
education communities. To facilitate both debugging and education,
`try.zeek.org <https://try.zeek.org>`_ (formerly try.bro.org) was launched in
2014.  This provided an interactive way for users to test a script with their
own packet captures against a variety of Zeek versions and easily share
sample code with others.  For Zeek clusters and external communication,
the Broker communication framework was added.  Last, but not least, the
Zeek package manager was created in 2016, funded by an additional grant
from the Mozilla Foundation.

In the fall of 2018, the project leadership team decided to change the name of
the software from Bro to Zeek. The leadership team desired a name that better
reflected the values of the community while avoiding the negative connotations
of so-called “bro culture” outside the computing world. The project released
version 3.0 in the fall of 2019, the first release bearing the name Zeek. The
year 2020 saw a renewed focus on community and growing the Zeek community, with
increased interaction via social media, webinars, Slack channels, and related
outreach efforts.

For a history of the project from 1995 to 2015, see Vern Paxson’s talk from
BroCon 2015, `Reflecting on Twenty Years of Bro
<https://www.youtube.com/watch?v=pb9HlmV0s2A>`_.

For background on the decision to rename Bro to Zeek, see Vern Paxson’s talk
from BroCon 2018, `Renaming Bro
<https://www.youtube.com/watch?v=L88ZYfjPzyk>`_.
