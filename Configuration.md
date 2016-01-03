# Introduction #

By default the _lpws_ binary will read it's configuration from _/etc/lpws.conf_ but this can be overridden with the _--config_ option.

There are only two files needed to get _lpws_ to run. The first is the config file, the second is the private key that will be used by the server.

# Private Key #

The private key will be read from _/etc/lpws.key_. You may override this location by using the _private\_key_ directive in the configuration file. This is a simple RSA private key and should be 1024 bits. To generate this key yourself run the following command as root.
```
openssl genrsa -out /etc/lpws.key 1024
```

Later versions of this software will provide a method for better self-configuration.

# Config File #

The available options used directly by the _lpws_ binary are:
  * **private\_key** - This config option allows you to override the default location of the private key file.
  * **sasl\_auxprop\_plugin** - While not strictly used by _lpws_ this option should be set and always set to **lpws\_ldap**.
  * **ldap\_uri** - The URI used when connecting to the LDAP server.
  * **ldap\_basedn** - The search base to use when looking up a user's record.
  * **ldap\_binddn** - The DN to use when binding. This must be a DN that has access to read/write the userPassword and authAuthority attributes.
  * **ldap\_bindpw** - The password to use when binding with the above DN.
  * **hostname** - Override the detected hostname of the system.
  * **ipaddress** - Override the resolved IP address of the hostname.

Any SASL option can be set by prefixing the requested option name with sasl`_`. The LDAP auxprop module used by _lpws_ for retrieving the user's unencrypted password has the following options (if these options are not found then they will be searched for by just the **ldap`_`** prefix, i.e. **ldap\_uri**):
  * **sasl\_lpws\_ldap\_uri** - The URI used when connecting to the LDAP server.
  * **sasl\_lpws\_ldap\_basedn** - The search base to use when looking up a user's record.
  * **sasl\_lpws\_ldap\_search** - The query to use when searching. A basic query would be **uid=%u**.
  * **sasl\_lpws\_ldap\_binddn** - The DN to use when binding. This must be a DN that has access to read the userPassword attribute.
  * **sasl\_lpws\_ldap\_bindpw** - The password to use when binding with the above DN.

An example config file might look like this.
```
private_key = /etc/lpws/private.key
sasl_auxprop_plugin = lpws_ldap
ldap_uri = ldap://127.0.0.1
ldap_basedn = dc=example,dc=com
ldap_binddn = uid=lpws,ou=users,dc=example,dc=com
ldap_bindpw = supersecret
sasl_lpws_ldap_search = uid=%u
```