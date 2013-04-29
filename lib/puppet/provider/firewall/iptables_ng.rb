require 'digest/md5'
require 'iptables'

Puppet::Type.type(:firewall).provide :iptables_ng do
  @doc = "Iptables type provider - next generation"

  has_feature :iptables
  has_feature :rate_limiting
  has_feature :snat
  has_feature :dnat
  has_feature :interface_match
  has_feature :icmp_match
  has_feature :owner
  has_feature :state_match
  has_feature :reject_type
  has_feature :log_level
  has_feature :log_prefix
  has_feature :mark
  has_feature :tcp_flags
  has_feature :pkttype
  has_feature :isfragment
  has_feature :socket

  optional_commands({
    :iptables => 'iptables',
    :iptables_save => 'iptables-save',
    :ip6tables => 'ip6tables',
    :ip6tables_save => 'ip6tables-save',
  })
  commands({
    :foo => 'bar'
  })

#  defaultfor :kernel => :foo
#  defaultfor :iptables_ng => :true

  def insert
  end

  def delete
  end

  def method_missing(method)
    debug 'method_missing called: ' + method.to_s
    'foo'
  end

  def exists?
    debug 'exists? called'
    true
  end

  def flush
    debug 'flush called'
  end

  def self.instances
    # Iptables compatibility
    iptables_version = Facter.fact('iptables_version').value
    iptables_compat = nil
    if (iptables_version and Puppet::Util::Package.versioncmp(iptables_version, '1.4.1') < 0)
      iptables_compat = '1.3.5'
    else
      iptables_compat = iptables_version
    end

    # Grab decodes rules from each iptables command
    rules4 = Iptables.decode(iptables_save,
      :iptables_compatibility => iptables_compat)
    rules6 = Iptables.decode(ip6tables_save,
      :iptables_compatibility => iptables_compat)

    puts rules4.inspect

    [new(:name => '000 foo')]
  end
end
