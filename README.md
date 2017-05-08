Building
========
Environment
-----------
Testing and building was done under Ubuntu 12.10 and 12.04, although other
distributions and versions may work. The following tools and libraries are
needed for building:

- gcc >=4
- linux-headers 3.5.0
- Autoconf >=2.69
- Automake >=1.11
- libtool >=2.4.2
- libpcap-dev >=1.3.0
- libpolarssl-dev >=1.1.4
- libpthread-dev >= 1.1.1

To install these under Ubuntu 12.10:

	￼$ sudo apt-get install automake autoconf build-essential libtool libpcap -dev libpolarssl -dev

Compile
-------
From ARG source directory:

	$ ./autogen.sh
	$ make

Usage
=====
Please see [thesis appendices](https://github.com/traherom/arg_thesis) for full description of usage and
configuration. The covers ARG itself, traffic generators,
and results processor.

