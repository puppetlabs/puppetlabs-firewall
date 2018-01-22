# An Address type.
type Firewall::Address_type = Enum[
  'UNSPEC',      # unspecified address
  'UNICAST',     # unicast address
  'LOCAL',       # local address
  'BROADCAST',   # broadcast address
  'ANYCAST',     # anycast packet
  'MULTICAST',   # multicast address
  'BLACKHOLE',   # blackhole address
  'UNREACHABLE', # unreachable address
  'PROHIBIT',    # prohibited address
  'THROW',       # undocumented
  'NAT',         # undocumented
  'XRESOLVE',    # undocumented
]
