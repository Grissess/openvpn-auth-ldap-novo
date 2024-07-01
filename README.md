# openvpn-auth-ldap-novo

An OpenVPN plugin for authentication by way of simple BIND auth to an LDAP
server.

This plugin is designed with simplicity as a foremost goal; as such,
flexibility is sparing.

## Usage

Load it as a plugin line using a config file:

```
plugin path/to/openvpn-auth-ldap-novo.so var=value var=value [...]
```

All configuration options are accepted as arguments to the plugin. At present
they are: 

- `ldap-uri`: The LDAP URI of the server to which to bind. Required.

- `base`: The base of the DIT search. Optional, `""` if unspecified, but this
  is probably not what you want.

- `scope`: One of `base`, `onelevel`, `subtree`, or `children`. Optional;
  defaults to `subtree`.

- `filter`: The filter to use to search for a DN. A single(!) `%s` is
  interpolated with the username of the OpenVPN auth attempt. The default is
  `(cn=%s)`, which may or may not be a sensible default.

- `bind-dn`: The BIND DN used to execute a search. Optional; if not given,
  openvpn-auth-ldap-novo will bind anonymously. If specified, requires either
  `bind-pw` or `bind-pw-file`.

- `bind-pw`: The password of the above DN.

- `bind-pw-file`: Path to a file containing the bind password. Ineffective if
  `bind-pw` is also specified. The file is read once during plugin
  startup--thus as the same credential as OpenVPN initially has.

## License

This plugin is GPL version 3 or later.

Code from OpenVPN itself is included under the GPL version 2, without regard to
the "linking against" exception. See their distribution for details.
