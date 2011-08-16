Puppet::Type.type(:firewall).provide :ip6tables, :parent => :iptables, :source => :iptables do
  @doc = "Ip6tables type provider"

  has_feature :iptables
  has_feature :rate_limiting
  has_feature :snat
  has_feature :dnat
  has_feature :interface_match
  has_feature :icmp_match
  has_feature :state_match
  has_feature :reject_type
  has_feature :log_level
  has_feature :log_prefix

  commands :iptables      => '/sbin/ip6tables'
  commands :iptables_save => '/sbin/ip6tables-save'

  @resource_map = {
    :burst => "--limit-burst",
    :destination => "-d",
    :dport => "-m multiport --dports",
    :icmp => "-m icmp6 --icmpv6-type",
    :iniface => "-i",
    :jump => "-j",
    :limit => "--limit",
    :log_level => "--log-level",
    :log_prefix => "--log-prefix",
    :name => "-m comment --comment",
    :outiface => "-o",
    :proto => "-p",
    :reject => "--reject-with",
    :source => "-s",
    :state => "-m state --state",
    :sport => "-m multiport --sports",
    :table => "-t",
    :todest => "--to-destination",
    :toports => "--to-ports",
    :tosource => "--to-source",
  }

  @resource_list = [:table, :source, :destination, :iniface, :outiface, 
    :proto, :sport, :dport, :name, :state, :icmp, :limit, :burst, :jump, 
    :todest, :tosource, :toports, :log_level, :log_prefix, :reject]

end
