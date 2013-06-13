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
  # TODO: This is just here while we are developing the idea, so it can be disabled.
  # Use FACTER_iptables_ng="true" in front of any puppet commands to use this
  # provider.
  confine :iptables_ng => :true

  @resource_map = [
    :burst,
    #:destination,
    #:dport,
    :gid,
    #:icmp,
    #:iniface,
    #:jump,
    :limit,
    :log_level,
    :log_prefix,
    #:name,
    #:outiface,
    #:port,
    #:proto,
    :reject,
    :set_mark,
    :socket,
    #:source,
    #:sport,
    #:state,
    #:table,
    :tcp_flags,
    :todest,
    :toports,
    :tosource,
    :uid,
    :pkttype,
    :isfragment,
  ]

  # Create property methods dynamically
  #(@resource_map << :chain << :table << :action).each do |property|
  (@resource_map).each do |property|
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

    # Here we iterate across the rules returned from iptables, and generate new
    # IptablesNg objects.
    #
    # TODO: rules4 & rules6 code re-use here.
    rules4[:result].each do |k,v|
      table = k
      v.each do |k,v|
        chain = k
        v[:rules].each do |rule|
          hash = {
            :ensure => 'present',
            :table => table,
            :network_protocol => 'ipv4',
            :rule_data => rule,
          }
          debug "Creating IPV4 hash with:\n#{hash.pretty_inspect}"
          results << new(hash)
        end
      end
    end

    rules6[:result].each do |k,v|
      table = k
      v.each do |k,v|
        chain = k
        v[:rules].each do |rule|
          hash = {
            :ensure => 'present',
            :table => table,
            :network_protocol => 'ipv6',
            :rule_data => rule,
          }
          debug "Creating IPV6 hash with:\n#{hash.pretty_inspect}"
          results << new(hash)
        end
      end
    end

    # TODO: look into merging rules:
    # * an ipv4 might be exactly the same as ipv6, therefore network_protocol => 'all'
    # * multiple source & destination rules might be merged into 1

    results
  end

  # @!group Public Property Methods

  def action
    if ['ACCEPT','REJECT','DROP'].include?(jump) then
      return jump.downcase
    end
  end

  def chain
    rule_data[:rule][:chain]
  end

  def destination
    d, negate = rule_param('d')
    if d.is_a? Array
      return d.first
    end
    d
  end

  def dport
    dports = []

    tcp = rule_matches('tcp')
    tcp.each do |m|
      d = m["dport"]
      dports << m["dport"][0].gsub(/:/,'-') unless d.nil? or d.empty?
    end

    multiport = rule_matches('multiport')
    multiport.each do |m|
      d = m["dports"]
      unless d.nil? or d.empty?
        d[0].split(",").each do |port|
          dports << port.gsub(/:/,'-')
        end
      end
    end

    dports = nil if dports.empty?
    return dports
  end

  def goto
    # TODO: -g doesn't seem to come through from iptables gem
    g, negate = rule_param('g')
    g
  end

  def icmp
    icmp = rule_matches('icmp')
    icmp.each do |m|
      t = m['icmp-type']
      return t.first unless t.nil? or t.empty?
    end

    nil
  end

  def iniface
    i, negate = rule_param('i')
    (negate ? "!" : '') + i.first unless i.nil?
  end

  def jump
    rule_data[:rule][:target]
  end

  def name
    # Firstly, try to get it from the comment
    name = nil
    rule_data[:rule][:matches].each do |match|
      if match[:name] == 'comment'
        name = match[:options]['comment'][0]
        break
      end
    end

    # If that doesn't work, hash the original rule and add a number
    unless name and name =~ /^\d+[[:alpha:][:digit:][:punct:][:space:]]+$/
      num = 9000 + rule_data[:source][:original_line_number]
      line = rule_data[:source][:original_line]
      name = "#{num} #{Digest::MD5.hexdigest(line)}"
    end

    name
  end

  def network_protocol
    @property_hash[:network_protocol]
  end

  def outiface
    i, negate = rule_param('o')
    (negate ? "!" : '') + i.first unless i.nil?
  end

  def port
    ports = []

    multiport = rule_matches('multiport')
    multiport.each do |m|
      s = m["ports"]
      unless s.nil? or s.empty?
        s[0].split(",").each do |port|
          ports << port.gsub(/:/,'-')
        end
      end
    end

    ports = nil if ports.empty?
    return ports
  end

  def proto
    p, negate = rule_param('p')
    if p.is_a? Array
      return p.first
    end

    p
  end

  def source
    s, negate = rule_param('s')
    if s.is_a? Array
      return s.first
    end
    s
  end

  def sport
    sports = []

    tcp = rule_matches('tcp')
    tcp.each do |m|
      s = m["sport"]
      sports << m["sport"][0].gsub(/:/,'-') unless s.nil? or s.empty?
    end

    multiport = rule_matches('multiport')
    multiport.each do |m|
      s = m["sports"]
      unless s.nil? or s.empty?
        s[0].split(",").each do |port|
          sports << port.gsub(/:/,'-')
        end
      end
    end

    sports = nil if sports.empty?
    return sports
  end

  def state
    # Grab from matchers
  end

  def table
    @property_hash[:table]
  end

  # @!group Private Helpers

  # Convenience to get at the rule_data from iptables gem output.
  #
  # @return [Hash] the rule data for this instance
  # @api private
  def rule_data
    @property_hash[:rule_data]
  end

  # Return the value of a parameter from the iptables hash.
  #
  # @param param [String] parameter to return
  # @return [Array <Array<String>, Boolean>] returns array of parameter values,
  #   the boolean if true, indicates the option is negated.
  # @api private
  def rule_param(param)
    if p = rule_data[:rule][:parameters][param]
      return [p, false]
    elsif p = rule_data[:rule][:parameters]["!" + param]
      return [p, true]
    end
  end

  # Return the matchers of a particular type from the iptables hash
  #
  # @param name [String] name of matcher to find
  # @return [Array <Hash>] returns an array of options for this match
  # @api private
  def rule_matches(name)
    m = []
    rule_data[:rule][:matches].each do |match|
      if match[:name] == name
        m << match[:options]
      end
    end
    m
  end
end
