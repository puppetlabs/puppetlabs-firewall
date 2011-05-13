require 'puppet/provider/firewall'

Puppet::Type.type(:firewall).provide :iptables, :parent => Puppet::Provider::Firewall do
  include Puppet::Util::Firewall
  
  @doc = "Iptables type provider"

  commands :iptables => '/sbin/iptables'
  commands :iptables_save => '/sbin/iptables-save'

  defaultfor :operatingsystem => [:redhat, :debian, :ubuntu, :fedora, :suse, :centos, :sles, :oel, :ovm]
  confine :operatingsystem => [:redhat, :debian, :ubuntu, :fedora, :suse, :centos, :sles, :oel, :ovm]

  @@resource_map = {
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

  @@resource_list = [:table, :source, :destination, :iniface, :outiface, :proto, :sport, :dport, :tosource, :todest,
                     :reject, :log_level, :log_prefix, :name, :state, :icmp, :limit, :burst, :toports, :jump]


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
    iptables "-D", properties[:chain], insert_order
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
    iptables_save.lines do |line|
      unless line =~ /^\#\s+|^\:\S+|^COMMIT/
        if line =~ /^\*/
          table = line.sub(/\*/, "").chomp!
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

    @@resource_list.reverse.each do |k|
      if values.slice!(@@resource_map[k])
        keys << k
      end
    end

    # Manually remove chain
    values.slice!('-A')
    keys << :chain

    keys.zip(values.scan(/"[^"]*"|\S+/).reverse) { |f, v| hash[f] = v.gsub(/"/, '') }
    [:dport, :sport, :destination, :source, :state].each do |prop|
      if hash[prop] =~ /,/
        hash[prop] = hash[prop].split(',')
      else
        hash[prop] = [hash[prop]]
      end
    end
    hash[:provider] = self.name.to_s
    hash[:table] = table
    hash[:ensure] = :present
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

  def general_args
    debug "Current resource: %s" % resource.class
    args = []
    @@resource_list.each do |res|
      if(resource.value(res))
        args << @@resource_map[res].split(' ')
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
