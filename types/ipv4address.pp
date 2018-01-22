# An IPv4 address in CIDR format, optionally negated by a "!" prefix.
type Firewall::Ipv4address = Pattern[/\A(![[:blank:]]*)?(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])(\/([1-2][0-9]?|3[0-2]{0,1}|[4-9]))?\z/]
