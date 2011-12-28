 
Puppet::Type.type(:firewallchain).provide :ebtables_chain, :parent => :iptables_chain, :source => :iptables_chain do
  @doc = "Ebtables chain type provider"

  has_feature :iptables_chain
  has_feature :policy
  has_feature :ethernet
  has_feature :broute

  commands :iptables      => '/sbin/ebtables'
  commands :iptables_save => '/sbin/ebtables-save'
  @protocol = 'EB'

end
