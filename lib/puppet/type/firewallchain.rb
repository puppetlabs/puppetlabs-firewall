
Puppet::Type.newtype(:firewallchain) do

  @doc = <<-EOS
    This type provides the capability to manage iptables chains and policies on
    internal chains within puppet.
  EOS

  #InternalChains = /^(PREROUTING|POSTROUTING|BROUTING|INPUT|FORWARD|OUTPUT)$/
  #Tables = 'NAT|MANGLE|FILTER|RAW|RAWPOST|BROUTE|'
  ## Technically colons (':') are allowed in table names however it requires
  ## ruby-1.9 to do a regex to allow a backslash escaping of the colon.
  ## ruby-1.9 regex:  Nameformat = /^(<table>#{Tables}):(<chain>([^:]*(?<!\\))+):(<protocol>IP(v[46])?|EB)?$/
  #Nameformat = /^(#{Tables}):([^:]+):(IP(v[46])?|ethernet:)$/

  feature :iptables_chain, "The provider provides iptables chain features."
  feature :policy, "Default policy (inbuilt chains only)"

  #autorequire(:firewallchain) do
  #  if @parameters[:name] =~ /:$/
  #    [ @parameters[:name] + 'IPv4', @parameters[:name] + 'IPv6']
  #  end
  #end

  ensurable do
    defaultvalues
    defaultto :present
  end

  newparam(:name) do
    desc <<-EOS
      The canonical name of the chain.
    EOS
    isnamevar

    validate do |value|
      if value !~ Nameformat then
        raise ArgumentError, "Inbuilt chains must be in the form {chain}:{table}:{protocol} where {table} is one of FILTER, NAT, MANGLE, RAW, RAWPOST, BROUTE or empty (alias for filter), chain can be anything without colons or one of PREROUTING, POSTROUTING, BROUTING, INPUT, FORWARD, OUTPUT for the inbuilt chains, and {protocol} being empty or IP (both meaning IPv4 and IPv6), IPv4, IPv6, ethernet (ethernet bridging) got '#{value}' table:'#{$1}' chain:'#{$2}' protocol:'#{$3}'"
      else 
        table = $1
        chain = $2
        protocol = $3
        case table
        when /^(FILTER|)$/
          if chain =~ /^(PREROUTING|POSTROUTING|BROUTING)$/
            raise ArgumentError, "INPUT, OUTPUT and FORWARD are the only inbuilt chains that can be used in table 'filter'"
          end
        when 'MANGLE'
          if chain =~ InternalChains && chain == 'BROUTING'
            raise ArgumentError, "PREROUTING, POSTROUTING, INPUT, FORWARD and OUTPUT are the only inbuilt chains that can be used in table 'mangle'"
          end
        when 'NAT'
          if chain =~ /^(BROUTING|INPUT|FORWARD)$/
            raise ArgumentError, "PREROUTING, POSTROUTING and OUTPUT are the only inbuilt chains that can be used in table 'nat'"
          end
          if protocol =~/^(IP(v6)?)?$/
            raise ArgumentError, "table nat isn't valid in IPv6 (or the default IP which is IPv4 and IPv6). You must specify ':IPv4' as the name suffix"
          end
        when 'RAW'
          if chain =~ /^(POSTROUTING|BROUTING|INPUT|FORWARD)$/
            raise ArgumentError,'PREROUTING and OUTPUT are the only inbuilt chains in the table \'raw\''
          end
        when 'BROUTE'
          if protocol != 'ethernet'
            raise ArgumentError,'BROUTE is only valid with protocol \'ethernet\''
          end
          if chain =~ /^PREROUTING|POSTROUTING|INPUT|FORWARD|OUTPUT$/
            raise ArgumentError,'BROUTING is the only inbuilt chain allowed on on table \'BROUTE\''
          end
        end  
        if chain == 'BROUTING' && ( protocol != 'ethernet' || table!='BROUTE')
          raise ArgumentError,'BROUTING is the only inbuilt chain allowed on on table \'BROUTE\' with protocol \'ethernet\' i.e. \'BROUTE:BROUTING:enternet\''
        end
      end
    end
  end

  newproperty(:policy) do
    desc <<-EOS
      This is the action to when the end of the chain is reached.
      It can only be set on inbuilt chains ( INPUT, FORWARD, OUTPUT,
      PREROUTING, POSTROUTING) and can be one of:

      * accept - the packet is accepted
      * drop - the packet is dropped
      * queue - the packet is passed userspace
      * return - the packet is returned to calling (jump) queue
                 or the default of inbuilt chains
    EOS
    newvalues(:accept, :drop, :queue, :return, :empty)
    defaultto do
      # ethernet chain have an ACCEPT default while other haven't got an allowed value
      if @resource[:name] =~ /:ethernet$/
        :accept
      else
        :empty
      end
    end
  end

  validate do
    debug("[validate]")

    value(:name).match(Nameformat)
    table = $1
    chain = $2
    protocol = $3

    # Check that we're not removing an internal chain
    if chain =~ InternalChains && value(:ensure).to_s == 'absent'
      self.fail "Cannot remove in-built chains"
    end

    if value(:policy) == :empty && protocol == 'ethernet'
      self.fail "you must set a non-empty policy on all ethernet table chains"
    end

    # Check that we're not setting a policy on a user chain
    if chain !~ InternalChains && value(:policy).to_s != 'empty' && protocol != 'ethernet'
      self.fail "policy can only be set on in-built chains (with the exceptionn of ethernet chains) (table:#{table} chain:#{chain} protocol:#{protocol})"
    end
 
    # no DROP policy on nat table
    if table == 'nat' &&
       value(:policy).to_s == 'DROP'
      self.fail 'The "nat" table is not intended for filtering, the use of DROP is therefore inhibited'
    end
  end
end

