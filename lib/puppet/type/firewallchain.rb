
Puppet::Type.newtype(:firewallchain) do

  @doc = <<-EOS
    This type provides the capability to manage firewall chains within
    puppet.
  EOS

  feature :iptables_chain, "The provider provides iptables chain features."
  feature :policy, "Default policy (inbuilt chains only)"

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
      if value =~ /^(PREROUTING|POSTROUTING|INPUT|FORWARD|OUTPUT)_?(\w*)/
        if $2 !~ /^(NAT|MANGLE|FILTER|RAW|RAWPOST|)_?(\w*)$/
          raise ArgumentError, "Inbuilt chains including %s must only be suffixed _{tablename}" % value
        elsif $2 !~ /^(IPv[46]|EB)/
          # ugly and provider specific
          raise ArgumentError, "Inbuilt chains must have a suffix _IPv4 or _IPv6 or _EB (ethernet chains)"
        end
      end
    end
  end

  newproperty(:table, :required_features => :iptables_chain) do
    desc <<-EOS
      Table to use. Can be one of:

      * nat
      * mangle
      * filter
      * raw
      * rawpost

      By default the setting is 'filter'.
    EOS

    newvalues(:nat, :mangle, :filter, :raw, :rawpost)
    defaultto :filter
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
    defaultto :empty
  end

  validate do
    debug("[validate]")

    if value(:ensure).to_s == "absent" &&
      value(:name) =~ /PREROUTING|POSTROUTING|INPUT|FORWARD|OUTPUT/

      self.fail "Cannot remove in-built chains"
    end
    # copied from firewall.rb
    # TODO: this is put here to skip validation if ensure is not set. This
    # is because there is a revalidation stage called later where the values
    # are not set correctly. I tried tracing it - but have put in this
    # workaround instead to skip. Must get to the bottom of this.
    if ! value(:ensure)
      return
    end

    # First we make sure the chains and tables are valid combinations
    if value(:table).to_s == "filter" &&
      value(:chain) =~ /PREROUTING|POSTROUTING/

      self.fail "PREROUTING and POSTROUTING cannot be used in table 'filter'"
    end

    if value(:table).to_s == "nat" && value(:chain) =~ /^(INPUT|FORWARD)/
      self.fail "INPUT and FORWARD cannot be used in table 'nat'"
    end

    if value(:table).to_s == "raw" &&
      value(:chain) =~ /^(INPUT|FORWARD|POSTROUTING)/

      self.fail 'INPUT, FORWARD and POSTROUTING cannot be used in table raw'
    end

    # Check that we're not setting a policy on a user chain
    if value(:policy).to_s != "empty"  &&
      value(:name) !~ /^(PREROUTING|POSTROUTING|INPUT|FORWARD|OUTPUT)/

      self.fail 'policy can only be set on in-built chains'
    end
    if value(:table).to_s == 'nat' &&
       value(:policy).to_s == 'DROP'
      self.fail 'The "nat" table is not intended for filtering, the use of DROP is therefore inhibited'
    end
  end
end
