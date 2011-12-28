 
Puppet::Type.type(:firewallchain).provide :ip6tables_chain, :parent => :iptables_chain, :source => :iptables_chain do
  @doc = "Ip6tables chain type provider"

  has_feature :iptables_chain
  has_feature :policy
  has_feature :ipv6
  has_feature :mangle
  has_feature :raw

  commands :iptables      => '/sbin/ip6tables'
  commands :iptables_save => '/sbin/ip6tables-save'
  @protocol = 'IPv6'

end
