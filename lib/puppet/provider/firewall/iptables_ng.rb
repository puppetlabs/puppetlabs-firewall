require 'digest/md5'
require 'iptables'

# Next generation iptables/ip6tables provider.
#
# This 'next generation' version of the iptables provider tries to provide a
# better parsing and encoding capability by moving that part of the function-
# ality into an independant library.
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

  defaultfor :kernel => :linux
  # This is just here while we are developing the idea, so it can be disabled.
  defaultfor :iptables_ng => :true

  @resource_map = [
    :burst,
    :destination,
    :dport,
    :gid,
    :icmp,
    :iniface,
    :jump,
    :limit,
    :log_level,
    :log_prefix,
    :name,
    :outiface,
    :port,
    :proto,
    :reject,
    :set_mark,
    :socket,
    :source,
    :sport,
    :state,
    :table,
    :tcp_flags,
    :todest,
    :toports,
    :tosource,
    :uid,
    :pkttype,
    :isfragment,
  ]

  # Create property methods dynamically
  (@resource_map << :chain << :table << :action).each do |property|
    define_method "#{property}" do
      @property_hash[property.to_sym]
    end

    define_method "#{property}=" do |value|
      @property_hash[:needs_change] = true
    end
  end

  # @!group Ensurable Methods

  def insert
  end

  def delete
  end

  # @!group Other Provider Methods

  # Checks for the existance of the iptables rule this resource represents.
  #
  # Since we work this out during self.instances, we just return the state of
  # the 'ensure' property here, no other steps necessary.
  #
  # @return [Boolean] true if iptables rule exists
  def exists?
    @property_hash[:ensure] != :absent
  end

  def flush
    debug 'flush called'
  end

  # @!group Static Methods

  # Get iptables_ng resource instances.
  #
  # This is called early, to determine what base iptables_ng resources there
  # are. Our goal is to introspect all existing iptables and ip6tables rules
  # returning an array of new Iptables_ng objects, one for each rule.
  #
  # @return [Array<Puppet::Provider::Provider::IptablesNg>] returns array of
  #   provider objects
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

    require 'pp'
    debug "iptables gem output:\n#{rules4.pretty_inspect}"

    results = []
    rules4[:result].each do |k,v|
      table = k
      v.each do |k,v|
        chain = k
        v[:rules].each do |rule|
          # Grab the name from the first comment matcher
          name = nil
          rule[:rule][:matches].each do |match|
            if match[:name] == 'comment'
              name = match[:options]['comment'][0]
              break
            end
          end
          name = '000 foo' if name.nil?

          hash = {
            :name => name,
            :ensure => 'present',
            :table => table,
            :chain => chain,
            :netproto => 'ipv4',
            :rule_data => rule,
          }
          debug "Creating hash with:\n#{hash.pretty_inspect}"
          results << new(hash)
        end
      end
    end

    rules6[:result].each do |k,v|
      table = k
      v.each do |k,v|
        chain = k
        v[:rules].each do |rule|
          # Grab the name from the first comment matcher
          name = nil
          rule[:rule][:matches].each do |match|
            if match[:name] == 'comment'
              name = match[:options]['comment'][0]
              break
            end
          end
          name = '000 foo' if name.nil?

          hash = {
            :name => name,
            :ensure => 'present',
            :table => table,
            :chain => chain,
            :network_protocol => 'ipv6',
            :rule_data => rule,
          }
          debug "Creating hash with:\n#{hash.pretty_inspect}"
          results << new(hash)
        end
      end
    end

    results
  end

  # @!group Property Methods

  def network_protocol
    @property_hash[:network_protocol]
  end
end
