=======
ssh.log
=======

Secure Shell (SSH) is one of the fundamental protocols of the Internet age.
System administrators use SSH to securely access systems, typically running a
SSH has always been encrypted, so security analysts have never examined its
contents as they may have done with Telnet or other clear text system
administration protocols.

Zeek seeks to provide a variety of details about SSH sessions.

For more detail on each field, please see :zeek:see:`SSH::Info`.

Lateral Movement
================

In the first example we will look at lateral movement. This term refers to a
connection between two systems on the same subnet, or at least within the same
network or organization.

.. literal-emph::

  {
    "ts": "2020-09-16T13:39:18.425492Z",
    "uid": "C72qTo2v3FBhwysEIc",
    "id.orig_h": "192.168.4.142",
    "id.orig_p": 54161,
    "id.resp_h": "192.168.4.1",
    "id.resp_p": 22,
    "version": 2,
    **"auth_success": true,**
    **"auth_attempts": 1,**
    "client": "SSH-2.0-SecureBlackbox",
    "server": "SSH-2.0-OpenSSH_6.6.1p1 Debian-4~bpo70+1",
    "cipher_alg": "aes128-ctr",
    "mac_alg": "umac-64@openssh.com",
    "compression_alg": "none",
    "kex_alg": "diffie-hellman-group1-sha1",
    "host_key_alg": "ssh-rsa",
    "host_key": "f9:1f:45:88:dd:da:82:c5:7c:9d:75:c3:ac:e6:f4:f6",
    "hasshVersion": "1.0",
    "hassh": "3f0109679e469fced2c82384f0fa3917",
    "hasshServer": "b003da101c8caf37ce9e3ca3cd9d049b",
    "cshka": "ssh-rsa,ssh-dss",
    "hasshAlgorithms": "diffie-hellman-group1-sha1,diffie-hellman-group-exchange-sha1,diffie-hellman-group-exchange-sha256,diffie-hellman-group14-sha1;aes128-ctr,aes192-ctr,aes256-ctr;umac-64@openssh.com,hmac-sha2-256,hmac-sha2-512,umac-128@openssh.com,hmac-md5,hmac-md5-96,hmac-sha1,hmac-sha1-96,hmac-ripemd160@openssh.com,hmac-ripemd160;none,zlib,zlib@openssh.com",
    "sshka": "ssh-rsa,ssh-dss,ecdsa-sha2-nistp256,ssh-ed25519",
    "hasshServerAlgorithms": "curve25519-sha256@libssh.org,ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521,diffie-hellman-group-exchange-sha256,diffie-hellman-group-exchange-sha1,diffie-hellman-group14-sha1,diffie-hellman-group1-sha1;chacha20-poly1305@openssh.com,aes128-ctr,aes192-ctr,aes256-ctr,aes128-gcm@openssh.com,aes256-gcm@openssh.com;hmac-md5-etm@openssh.com,hmac-sha1-etm@openssh.com,umac-64-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,hmac-ripemd160-etm@openssh.com,hmac-sha1-96-etm@openssh.com,hmac-md5-96-etm@openssh.com,hmac-md5,hmac-sha1,umac-64@openssh.com,umac-128@openssh.com,hmac-sha2-256,hmac-sha2-512,hmac-ripemd160,hmac-ripemd160@openssh.com,hmac-sha1-96,hmac-md5-96;none,zlib@openssh.com"
  }

There’s a lot to this log. I’ve bolded the central elements as these are
probably the most immediately actionable elements. They indicate that a client
(``192.168.4.142``) successfully logged into a SSH server (``192.168.4.1``).

The rest of the data generally profiles the nature of the client and server and
the encryption they used for the session. For example, the various ``hassh``
fields come from the `HASSH Zeek package
<https://github.com/salesforce/hassh>`_ and are similar to the JA3 and JA3S
packages mentioned in the :file:`ssl.log` chapter.

The ``hassh`` field provides a hash characterizing the encryption offered by
the SSH client. The hasshServer field characterizes the encryption offered by
the SSH server.

Failed Lateral Movement
=======================

In the following example, I created failed logins to generate Zeek logs. Here I
entered a wrong password, then hit the return key twice.

.. code-block:: console

  $ ssh me@192.168.4.1

::

  Welcome to MyServer

  me@192.168.4.1's password: **[wrong password entered]**
  me@192.168.4.1's password: **[no password, return]**
  me@192.168.4.1's password: **[no password, return]**
  Permission denied (publickey,password).

Zeek produced the following log:

.. literal-emph::

  {
    "ts": "2020-09-16T14:23:41.005323Z",
    "uid": "COfRkd4UVXYwu1GTqh",
    "id.orig_h": "192.168.4.142",
    "id.orig_p": 57442,
    "id.resp_h": "192.168.4.1",
    "id.resp_p": 22,
    "version": 2,
    **"auth_attempts": 0,**
    "client": "SSH-2.0-OpenSSH_7.5",
    "server": "SSH-2.0-OpenSSH_6.6.1p1 Debian-4~bpo70+1",
    "cipher_alg": "aes128-ctr",
    "mac_alg": "hmac-md5",
    "compression_alg": "zlib@openssh.com",
    "kex_alg": "curve25519-sha256@libssh.org",
    "host_key_alg": "ssh-rsa",
    "host_key": "f9:1f:45:88:dd:da:82:c5:7c:9d:75:c3:ac:e6:f4:f6",
    "hasshVersion": "1.0",
    "hassh": "0d7f08c427fb41f68ec40fbe8fb7b5cb",
    "hasshServer": "b003da101c8caf37ce9e3ca3cd9d049b",
    "cshka": "ssh-rsa-cert-v01@openssh.com,ssh-rsa,ecdsa-sha2-nistp256-cert-v01@openssh.com,ssh-dss-cert-v01@openssh.com,ssh-dss,ecdsa-sha2-nistp384-cert-v01@openssh.com,ecdsa-sha2-nistp521-cert-v01@openssh.com,ssh-ed25519-cert-v01@openssh.com,ecdsa-sha2-nistp256,ecdsa-sha2-nistp384,ecdsa-sha2-nistp521,ssh-ed25519",
    "hasshAlgorithms": "curve25519-sha256,curve25519-sha256@libssh.org,ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521,diffie-hellman-group-exchange-sha256,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,diffie-hellman-group-exchange-sha1,diffie-hellman-group14-sha256,diffie-hellman-group14-sha1,ext-info-c;aes128-ctr,aes192-ctr,aes256-ctr,arcfour256,arcfour128,aes256-gcm@openssh.com,aes128-cbc,3des-cbc,arcfour,aes128-gcm@openssh.com,chacha20-poly1305@openssh.com,blowfish-cbc,cast128-cbc,aes192-cbc,aes256-cbc,rijndael-cbc@lysator.liu.se;hmac-md5,hmac-sha1,umac-64@openssh.com,umac-128@openssh.com,hmac-sha2-256,hmac-sha2-512,hmac-ripemd160,hmac-sha1-96,hmac-md5-96,umac-64-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,hmac-md5-etm@openssh.com,hmac-sha1-etm@openssh.com,hmac-ripemd160-etm@openssh.com,hmac-sha1-96-etm@openssh.com,hmac-md5-96-etm@openssh.com,hmac-ripemd160@openssh.com;zlib@openssh.com,zlib,none",
    "sshka": "ssh-rsa,ssh-dss,ecdsa-sha2-nistp256,ssh-ed25519",
    "hasshServerAlgorithms": "curve25519-sha256@libssh.org,ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521,diffie-hellman-group-exchange-sha256,diffie-hellman-group-exchange-sha1,diffie-hellman-group14-sha1,diffie-hellman-group1-sha1;chacha20-poly1305@openssh.com,aes128-ctr,aes192-ctr,aes256-ctr,aes128-gcm@openssh.com,aes256-gcm@openssh.com;hmac-md5-etm@openssh.com,hmac-sha1-etm@openssh.com,umac-64-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,hmac-ripemd160-etm@openssh.com,hmac-sha1-96-etm@openssh.com,hmac-md5-96-etm@openssh.com,hmac-md5,hmac-sha1,umac-64@openssh.com,umac-128@openssh.com,hmac-sha2-256,hmac-sha2-512,hmac-ripemd160,hmac-ripemd160@openssh.com,hmac-sha1-96,hmac-md5-96;none,zlib@openssh.com"
  }

Notice there is no entry like this from the successful login::

  "auth_success": true,

That is helpful. However, there is the following entry, which is odd::

  "auth_attempts": 0,

There was definitely at least one authentication attempt. I cannot explain this
result.

Outbound Movement
=================

One aspect of Zeek’s :file:`ssh.log` that I find useful is the determination if
the SSH login was “inbound” or “outbound”. In the following example, we see a
login from the enterprise using the ``192.168.4.0/24`` network, to a host on the
Internet:

.. literal-emph::

  {
    "ts": "2020-09-16T13:08:58.933098Z",
    "uid": "Cjmfpo49s3lei7CBla",
    **"id.orig_h": "192.168.4.49",**
    "id.orig_p": 39550,
    **"id.resp_h": "205.166.94.16",**
    **"id.resp_p": 22,**
    "version": 2,
    **"auth_success": true,**
    "auth_attempts": 2,
    **"direction": "OUTBOUND",**
    "client": "SSH-2.0-OpenSSH_7.4p1 Raspbian-10+deb9u7",
    "server": "SSH-2.0-OpenSSH_8.0",
    "cipher_alg": "chacha20-poly1305@openssh.com",
    "mac_alg": "umac-64-etm@openssh.com",
    "compression_alg": "none",
    "kex_alg": "curve25519-sha256",
    "host_key_alg": "ssh-ed25519",
    "host_key": "e4:ff:65:d7:be:5d:c8:44:1d:89:6b:50:f5:50:a0:ce",
    "hasshVersion": "1.0",
    "hassh": "0df0d56bb50c6b2426d8d40234bf1826",
    "hasshServer": "b12d2871a1189eff20364cf5333619ee",
    "cshka": "ssh-ed25519-cert-v01@openssh.com,ssh-ed25519,ecdsa-sha2-nistp256-cert-v01@openssh.com,ecdsa-sha2-nistp384-cert-v01@openssh.com,ecdsa-sha2-nistp521-cert-v01@openssh.com,ssh-rsa-cert-v01@openssh.com,ecdsa-sha2-nistp256,ecdsa-sha2-nistp384,ecdsa-sha2-nistp521,rsa-sha2-512,rsa-sha2-256,ssh-rsa",
    "hasshAlgorithms": "curve25519-sha256,curve25519-sha256@libssh.org,ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521,diffie-hellman-group-exchange-sha256,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,diffie-hellman-group-exchange-sha1,diffie-hellman-group14-sha256,diffie-hellman-group14-sha1,ext-info-c;chacha20-poly1305@openssh.com,aes128-ctr,aes192-ctr,aes256-ctr,aes128-gcm@openssh.com,aes256-gcm@openssh.com,aes128-cbc,aes192-cbc,aes256-cbc;umac-64-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,hmac-sha1-etm@openssh.com,umac-64@openssh.com,umac-128@openssh.com,hmac-sha2-256,hmac-sha2-512,hmac-sha1;none,zlib@openssh.com,zlib",
    "sshka": "ssh-ed25519,rsa-sha2-512,rsa-sha2-256,ssh-rsa,ssh-ed25519",
    "hasshServerAlgorithms": "curve25519-sha256,curve25519-sha256@libssh.org,ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521,diffie-hellman-group-exchange-sha256,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,diffie-hellman-group14-sha256,diffie-hellman-group14-sha1;chacha20-poly1305@openssh.com,aes128-ctr,aes192-ctr,aes256-ctr,aes128-gcm@openssh.com,aes256-gcm@openssh.com;umac-64-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,hmac-sha1-etm@openssh.com,umac-64@openssh.com,umac-128@openssh.com,hmac-sha2-256,hmac-sha2-512,hmac-sha1;none,zlib@openssh.com"
  }

Analysts can use this sort of log entry to identify when systems for which they
are responsible are connecting to SSH servers outside their organization.

Inbound Movement
================

In the following example, Zeek notices an inbound SSH connection:

.. literal-emph::

  {
    "ts": "2020-09-16T13:29:23.245216Z",
    "uid": "CzEmsljW9ooL0WnBd",
    **"id.orig_h": "35.196.195.158",**
    "id.orig_p": 53160,
    **"id.resp_h": "192.168.4.37",**
    **"id.resp_p": 22,**
    "version": 2,
    **"auth_success": true,**
    "auth_attempts": 1,
    **"direction": "INBOUND",**
    "client": "SSH-2.0-OpenSSH_7.9p1 Debian-10+deb10u2",
    "server": "SSH-2.0-OpenSSH_7.6p1 Ubuntu-4ubuntu0.3",
    "cipher_alg": "chacha20-poly1305@openssh.com",
    "mac_alg": "umac-64-etm@openssh.com",
    "compression_alg": "none",
    "kex_alg": "curve25519-sha256",
    "host_key_alg": "ecdsa-sha2-nistp256",
    "host_key": "a3:41:03:32:1f:8c:8e:82:92:9f:62:8c:38:82:d3:74",
    "hasshVersion": "1.0",
    "hassh": "ec7378c1a92f5a8dde7e8b7a1ddf33d1",
    "hasshServer": "b12d2871a1189eff20364cf5333619ee",
    "cshka": "ecdsa-sha2-nistp256-cert-v01@openssh.com,ecdsa-sha2-nistp384-cert-v01@openssh.com,ecdsa-sha2-nistp521-cert-v01@openssh.com,ssh-ed25519-cert-v01@openssh.com,rsa-sha2-512-cert-v01@openssh.com,rsa-sha2-256-cert-v01@openssh.com,ssh-rsa-cert-v01@openssh.com,ecdsa-sha2-nistp256,ecdsa-sha2-nistp384,ecdsa-sha2-nistp521,ssh-ed25519,rsa-sha2-512,rsa-sha2-256,ssh-rsa",
    "hasshAlgorithms": "curve25519-sha256,curve25519-sha256@libssh.org,ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521,diffie-hellman-group-exchange-sha256,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,diffie-hellman-group14-sha256,diffie-hellman-group14-sha1,ext-info-c;chacha20-poly1305@openssh.com,aes128-ctr,aes192-ctr,aes256-ctr,aes128-gcm@openssh.com,aes256-gcm@openssh.com;umac-64-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,hmac-sha1-etm@openssh.com,umac-64@openssh.com,umac-128@openssh.com,hmac-sha2-256,hmac-sha2-512,hmac-sha1;none,zlib@openssh.com,zlib",
    "sshka": "ssh-rsa,rsa-sha2-512,rsa-sha2-256,ecdsa-sha2-nistp256,ssh-ed25519",
    "hasshServerAlgorithms": "curve25519-sha256,curve25519-sha256@libssh.org,ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521,diffie-hellman-group-exchange-sha256,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,diffie-hellman-group14-sha256,diffie-hellman-group14-sha1;chacha20-poly1305@openssh.com,aes128-ctr,aes192-ctr,aes256-ctr,aes128-gcm@openssh.com,aes256-gcm@openssh.com;umac-64-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,hmac-sha1-etm@openssh.com,umac-64@openssh.com,umac-128@openssh.com,hmac-sha2-256,hmac-sha2-512,hmac-sha1;none,zlib@openssh.com"
  }

If an analyst does not expect this sort of activity, then it could indicate a
problem.

Failed Movement
===============

In the following example, we see something a bit different:

.. literal-emph::

  {
    "ts": "2020-09-16T13:29:08.560780Z",
    "uid": "CFb8DZ1DLzStfZaERb",
    **"id.orig_h": "205.166.94.9",**
    "id.orig_p": 55699,
    **"id.resp_h": "192.168.4.37",**
    **"id.resp_p": 22,**
    **"auth_attempts": 0,**
    **"direction": "INBOUND",**
    **"server": "SSH-2.0-OpenSSH_7.6p1 Ubuntu-4ubuntu0.3"**
  }

Notice that there is no successful authentication message. There is also no
client identification string. We only see the server’s message. I generated
this activity using Netcat. I connected to port 22 TCP and did not send any
data.

Conclusion
==========

This section has provided some details on the elements of the :file:`ssh.log`
that could be of use to analysts.
