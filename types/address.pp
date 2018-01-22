# An IPv4 or IPv6 address, optionallly optionally negated by a "!" prefix.
type Firewall::Address = Variant[Firewall::Ipv4address,Firewall::Ipv6address]

