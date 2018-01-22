# Input interface to filter on, optionally negated by a "!" prefix.
# Supports interface alias like eth0:0.
type Firewall::Iface = Pattern[/\A(![[:blank:]]*)?(\w|[.:+-]){1,15}\z/]
