# = Type: firewall::ignore
#
# Exempts matching rules from purging.
#
# Full example:
# firewall::ignore { 'my ignore rules':
#   chain => 'INPUT:filter:IPv4',
#   regex => [
#     '-j fail2ban-ssh', # ignore the fail2ban jump rule
#     '--comment "[^"]*(?i:ignore)[^"]*"', # ignore any rules with "ignore" (case insensitive) in the comment in the rule
#   ],
# }
#
# == Parameters:
#
# [*chain*]
#   The canonical name of the chain.
#   For iptables the format must be {chain}:{table}:{protocol}.
#
# [*regex*]
#   Regex to perform on firewall rules to exempt unmanaged rules from purging.
#   This works only when purging is enabled and target `firewallchain` is defined.
#   This is matched against the output of `iptables-save`.
#
#   This can be a single regex, or an array of them.
#   For more explanation see `firewallchain`.
#
define firewall::ignore(
  $chain = undef,
  $regex = undef,
){
  firewallchain_ignore { $title:
    chain => $chain,
    regex => $regex
  }
}
