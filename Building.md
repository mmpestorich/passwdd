# Pre-Requisites #

You will need the development libraries for the following packages:
  * cyrus-sasl
  * openssl
  * cryptopp
  * openldap

You will also need the following SASL mechanisms installed:
  * cyrus-sasl-md5

If you are on a Fedora machine you can get those with
```
yum install cyrus-sasl-devel openssl-devel cryptopp-devel openldap-devel cyrus-sasl-md5
```

# Build #

Once you have those download the source code and extract it. Then run the **make** command from the lpws folder.

The Makefile is currently setup for a Fedora 64-bit system, but it should work on a 32-bit system as well and hopefully other systems.

# Installing #

Once you have run **make** to build you can run **make install** to install everything. The Makefile should currently support 32-bit or 64-bit Fedora systems. I don't know about other distributions yet, so your mileage may vary.

By default the SASL plug-ins will be installed in /usr/lib{64}/sasl2 and binaries will be installed in /usr/local/sbin, you can override where the binaries go but not the plug-ins:
```
make install prefix=/usr
```
... will install the binaries in /usr/sbin.

If you want to do a test-install to see where everything goes without actually dumping stuff into your system directories you can use the standard DESTDIR option to put everything under a different root, for example to install everything relative to a root of /tmp/lpws-install
```
make install DESTDIR=/tmp/lpws-install
```