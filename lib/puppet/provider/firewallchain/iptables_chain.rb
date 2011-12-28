
Puppet::Type.type(:firewallchain).provide :iptables_chain do
  @doc = "Iptables chain type provider"

  has_feature :iptables_chain
  has_feature :policy
  has_feature :ipv4
  has_feature :nat
  has_feature :mangle
  has_feature :raw
  has_feature :rawpost

  commands :iptables => '/sbin/iptables'
  commands :iptables_save => '/sbin/iptables-save'
  @protocol = 'IPv4'

  def create
    debug 'Inserting chain %s' % resource[:name]
    iptables ['-N',@resource[:name]] 
    if @resource[:policy]
      iptables ['-t',@resource[:table],'-P',@resource[:name],@resource[:policy]] 
    end
  end

  def destroy
    debug 'Deleting chain %s' % resource[:name]
    iptables ['-t',@resource[:table],'-X',@resource[:name]] 
  end

  def exists?
    properties[:ensure] != :absent
  end

  def policy=(value)
    debug "set policy #{value}"
    return if value == :empty
    iptables ['-t',@resource[:table],'-P', tablename, value.upcase] 
  end

  def policy
    return @property_hash[:policy].to_s.downcase
  end

  def table=(value)
    debug "set table #{value}"
    destroy
    @resource[:table] = value
    create
  end

  def table
    return @property_hash[:table]
  end

  def tablename
    if @resource[:name] =~ /^(PREROUTING|POSTROUTING|INPUT|FORWARD|OUTPUT)/ then
       return $1
    else
       return @resource[:name]
    end 
  end

  def self.prefetch(resources)
    debug("[prefetch(resources)]")
    instances.each do |prov|
      if resource = resources[prov.name]
        resource.provider = prov
      end
    end
  end

  # Look up the current status. This allows us to conventiently look up
  # existing status with properties[:foo].
  def properties
    if @property_hash.empty?
      @property_hash = query || {:ensure => :absent}
      @property_hash[:ensure] = :absent if @property_hash.empty?
    end
    @property_hash.dup
  end

  # Pull the current state of the list from the full list.
  def query
    self.class.instances.each do |instance|
      if instance.name == self.name and instance.table == self.table
        debug "query found " % instance.properties.inspect
        return instance.properties
      end
    end
    nil
  end

  def self.instances
    debug "[instances]"
    table = nil
    chains = []

    iptables_save.split("\n").each do |line|
      if line =~ /^:(\w+)\s+(\S+)/ then
        name = $1
        policy = $2
        if $1 =~ /^(PREROUTING|POSTROUTING|INPUT|FORWARD|OUTPUT)$/ then
          if table != 'filter' then
            # ensure unique names for inbuilt rules on non-filter tables
            name += '_' + table.upcase
          end
          name += '_' + @protocol
        end
        chains << new({:name => name, :table => table, :policy => (policy == '-' ? :empty : policy.to_sym)  })
        debug "instance: %s table %s policy %s" % [ name, table, policy ]
      elsif line =~ /^\*(\S+)/
        table = $1
      end
    end
    chains
  end

end
