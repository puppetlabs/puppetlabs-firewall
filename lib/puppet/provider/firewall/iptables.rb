require 'puppet/provider/firewall'
require 'digest/md5'

Puppet::Type.type(:firewall).provide :iptables, :parent => Puppet::Provider::Firewall do
  include Puppet::Util::Firewall
  
  @doc = "Iptables type provider"

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

  commands :iptables => '/sbin/iptables'
  commands :iptables_save => '/sbin/iptables-save'

  defaultfor :kernel => :linux

  @resource_map = {
    :burst => "--limit-burst",
    :destination => "-d",
    :dport => "-m multiport --dports",
    :icmp => "-m icmp --icmp-type",
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

  def insert
    debug 'Inserting rule %s' % resource[:name]
    iptables insert_args
  end

  def update
    debug 'Updating rule %s' % resource[:name]
    iptables update_args 
  end

  def delete
    debug 'Deleting rule %s' % resource[:name]
    iptables delete_args
  end

  def exists?
    properties[:ensure] != :absent
  end

  # Flush the property hash once done.
  def flush
    debug("[flush]")
    if @property_hash.delete(:needs_change)
      notice("Properties changed - updating rule")
      update
    end
    @property_hash.clear
  end
  
  def self.instances
    debug "[instances]"
    table = nil
    rules = []
    counter = 1

    # String#lines would be nice, but we need to support Ruby 1.8.5
    iptables_save.split("\n").each do |line|
      unless line =~ /^\#\s+|^\:\S+|^COMMIT/
        if line =~ /^\*/
          table = line.sub(/\*/, "")
        else
          if hash = rule_to_hash(line, table, counter)
            rules << new(hash)
            counter += 1
          end
        end
      end
    end
    rules
  end

  def self.rule_to_hash(line, table, counter)
    hash = {}
    keys = []
    values = line.dup

    @resource_list.reverse.each do |k|
      if values.slice!(/\s#{@resource_map[k]}/)
        keys << k
      end
    end

    # Manually remove chain
    values.slice!('-A')
    keys << :chain

    keys.zip(values.scan(/"[^"]*"|\S+/).reverse) { |f, v| hash[f] = v.gsub(/"/, '') }
    
    [:dport, :sport, :state].each do |prop|
      hash[prop] = hash[prop].split(',') if ! hash[prop].nil?
    end

    # This forces all existing, commentless rules to be moved to the bottom of the stack.
    # Puppet-firewall requires that all rules have comments (resource names) and will fail if
    # a rule in iptables does not have a comment. We get around this by appending a high level
    if ! hash[:name]
      hash[:name] = "9999 #{Digest::MD5.hexdigest(line)}"
    end

    hash[:line] = line
    hash[:provider] = self.name.to_s
    hash[:table] = table
    hash[:ensure] = :present

    # Munge some vars here ...
    # proto should equal 'all' if undefined
    hash[:proto] = "all" if !hash.include?(:proto)
    hash
  end

  def insert_args
    args = []
    args << ["-I", resource[:chain], insert_order]
    args << general_args
    args
  end

  def update_args
    args = []
    args << ["-R", resource[:chain], insert_order]
    args << general_args
    args
  end

  def delete_args
    count = []
    line = properties[:line].gsub(/\-A/, '-D').split
    
    # Grab all comment indices
    line.each do |v|
      if v =~ /"/
        count << line.index(v)
      end
    end
    
    if ! count.empty?
      # Remove quotes and set first comment index to full string
      line[count.first] = line[count.first..count.last].join(' ').gsub(/"/, '')

      # Make all remaining comment indices nil
      ((count.first + 1)..count.last).each do |i|
        line[i] = nil
      end
    end
    
    # Return array without nils
    line.compact
  end

  def general_args
    debug "Current resource: %s" % resource.class
    args = []
    self.class.instance_variable_get('@resource_list').each do |res|
      if(resource.value(res))
        args << self.class.instance_variable_get('@resource_map')[res].split(' ')
        if resource[res].is_a?(Array)
          args << resource[res].join(',')
        else
          args << resource[res]
        end
      end
    end
    args
  end

  def insert_order
    debug("[insert_order]")
    rules = []
    
    # Find list of current rules based on chain
    self.class.instances.each do |rule|
      rules << rule.name if rule.chain == resource[:chain].to_s
    end

    # No rules at all? Just bail now.
    return 1 if rules.empty?

    my_rule = resource[:name].to_s
    rules << my_rule
    rules.sort.index(my_rule) + 1
  end
end
