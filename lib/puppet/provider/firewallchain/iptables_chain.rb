
Puppet::Type.type(:firewallchain).provide :iptables_chain do
  @doc = "Iptables chain provider"

  has_feature :iptables_chain
  has_feature :policy

  commands :iptables => '/sbin/iptables'
  commands :iptables_save => '/sbin/iptables-save'

  commands :ip6tables => '/sbin/ip6tables'
  commands :ip6tables_save => '/sbin/ip6tables-save'

  optional_commands( { :ebtables => '/sbin/ebtables',
                       :ebtables_save => '/sbin/ebtables-save'
  } )

  defaultfor :kernel => :linux

  # chain name is greedy so we anchor from the end.
  # [\d+:\d+] doesn't exist on ebtables
  Mapping = { :IPv4     => { :tables => method( :iptables ),  :save => method( :iptables_save),   :re => /^:(.+)\s(\S+)\s\[\d+:\d+\]$/  },
              :IPv6     => { :tables => method( :ip6tables ), :save => method( :ip6tables_save ), :re => /^:(.+)\s(\S+)\s\[\d+:\d+\]$/   },
              :ethernet => { :tables => method( :ebtables ),  :save => method( :ebtables_save ),  :re => /^:(.+)\s(\S+)$/   }
             }
  InternalChains = /^(PREROUTING|POSTROUTING|BROUTING|INPUT|FORWARD|OUTPUT)$/
  Tables = 'NAT|MANGLE|FILTER|RAW|RAWPOST|BROUTE|'
  Nameformat = /^(#{Tables}):(.+):(IP(v[46])?|ethernet|)$/

  def create
    # can't create internal chains
    if @resource[:name] =~ InternalChains
      self.warn "Attempting to create internal chain #{@resource[:name]}"
    end
    allvalidchains do |t, table, chain, protocol|
      if properties[:ensure] == protocol
        debug "Skipping Inserting chain #{chain} on table #{table} (#{protocol}) already exists"
      else
        debug "Inserting chain #{chain} on table #{table} (#{protocol}) using #{t}"
        t.call ['-t',table,'-N',chain]
        if @resource[:policy] != :empty
          t.call ['-t',table,'-P',chain,@resource[:policy].to_s.upcase] 
        end
      end
    end
  end

  def destroy
    # can't delete internal chains
    if @resource[:name] =~ InternalChains
      self.warn "Attempting to destroy internal chain #{@resource[:name]}"
    end
    allvalidchains do |t, table, chain|
      debug "Deleting chain #{chain} on table #{table}"
      t.call ['-t',table,'-X',chain] 
    end
  end

  def exists?
    # we want puppet to call create on 1/2 completed rules (i.e. :ensure => :IPv4/6)
    properties[:ensure] == :present
  end

  def policy=(value)
    return if value == :empty
    allvalidchains do |t, table, chain|
      p =  ['-t',table,'-P',chain,value.to_s.upcase]
      debug "[set policy] #{t} #{p}"
      t.call p
    end
  end

  def policy
    debug "[get policy] #{@resource[:name]} =#{@property_hash[:policy].to_s.downcase}"
    return @property_hash[:policy].to_s.downcase
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
      #@property_hash[:ensure] = :absent if @property_hash.empty?
    end
    @property_hash.dup
  end

  # Pull the current state of the list from the full list.
  def query
    self.class.instances.each do |instance|
      if instance.name == self.name
        debug "query found #{self.name}" % instance.properties.inspect
        return instance.properties
      end
    end
    nil
  end

  def self.instances
    debug "[instances]"
    table = nil
    chains = []
    hash = {}

    Mapping.each { |p, c|
      begin
        c[:save].call.split("\n").each do |line|
          if line =~ c[:re] then
            name = (table == 'filter' ? '' : table.upcase) + ':' + $1
            policy = $2 == '-' ? :empty : $2.downcase.to_sym
            if ( p == :IPv4 or p == :IPv6 ) && table != 'nat'
              if hash[name]
                # duplicate so create a {table}:{chain}:IP instance
                ippolicy = hash[name][:policy] == policy ? policy : :inconsistent
                hash.delete(name)
                chains << new({:name => name + ':', :policy => ippolicy, :ensure => :present })
                debug "[dup] '#{name}:' #{ippolicy}"
              else
                hash[name] = { :policy => policy, :protocol => p }
              end
            end
            name += ':' + p.to_s
            chains << new({:name => name, :policy => policy, :ensure => :present })
            debug "[instance] '#{name}' #{policy}"
          elsif line =~ /^\*(\S+)/
            table = $1
          elsif line =~ /^($|-A|COMMIT|#)/
            # other stuff we don't care about
          else
            debug "unrecognised line: #{line}"
          end
        end
      rescue Puppet::Error
        # ignore command not found for ebtables or anything that doesn't exist
      end
    }
    # put all the chain names that exist in one IP stack into a 1/2 completed (:ensure) state
    # The create method will check this and complete only what's required
    hash.each { |key, value|
      x = {:name => key + ':', :ensure => value[:protocol], :policy => :empty}
      debug "halfstate #{x.inspect}"
      chains << new(x)
    }
    chains
  end

  def allvalidchains
    @resource[:name].match(Nameformat)
    table = ($1=='') ? 'filter' : $1.downcase
    chain = $2
    protocol = $3
    if protocol == 'IP' || protocol == ''
      yield Mapping[:IPv4][:tables],table,chain,:IPv4
      yield Mapping[:IPv6][:tables],table,chain,:IPv6
    else
      yield Mapping[protocol][:tables],table,chain,protocol.to_sym
    end
  end
 
end
