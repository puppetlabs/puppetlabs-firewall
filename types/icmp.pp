# Icmp matching type
type Firewall::Icmp = Variant[
  Integer[0,18],
  Pattern[/\A([0-9]|1[0-8]|(address-mask|echo|timestamp)-re(ply|quest)|destination-unreachable|parameter-problem|redirect|router-(advertisement|solicitation)|source-quench|time-exceeded)\z]
]
