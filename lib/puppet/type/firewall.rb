# Puppet Firewall type
require 'puppet/util/firewall'
require 'puppet/property/ordered_list'

Puppet::Type.newtype(:firewall) do
  include Puppet::Util::Firewall

  @doc = "Manipulate firewall rules"

  ensurable do
    desc "Create or remove this rule."

    newvalue(:present) do
      provider.insert
    end

    newvalue(:absent) do
      provider.delete
    end

    defaultto :present
  end

  newparam(:name) do
    desc "The name of the rule."
    isnamevar

    # Keep rule names simple
    validate do |value|
      if value !~ /^[a-zA-Z0-9 \-_]+$/ then
        self.fail "Not a valid rule name. Make sure it contains ASCII " \
          "alphanumeric, spaces, hyphens or underscores."
      end
    end
  end

  newproperty(:chain) do
    desc "The value for the iptables -A parameter.
      Possible values are: 'INPUT', 'FORWARD', 'OUTPUT', 'PREROUTING', 'POSTROUTING'.
      Default value is 'INPUT'"
    newvalues(:INPUT, :FORWARD, :OUTPUT, :PREROUTING, :POSTROUTING)
    defaultto "INPUT"
  end

  newproperty(:table) do
    desc "The value for the iptables -t parameter.
      Possible values are: 'nat', 'mangle', 'filter' and 'raw'.
      Default value is 'filter'"
    newvalues(:nat, :mangle, :filter, :raw)
    defaultto "filter"
  end

  newproperty(:proto) do
    desc "The value for the iptables --protocol parameter.
      Possible values are: 'tcp', 'udp', 'icmp', 'esp', 'ah', 'vrrp',
      'igmp', 'all'.
      Default value is 'tcp'"
    newvalues(:tcp, :udp, :icmp, :esp, :ah, :vrrp, :igmp, :all)
    defaultto "tcp"
  end

  newproperty(:jump) do
    desc "The value for the iptables --jump parameter.
      Possible values are: 'ACCEPT', 'DROP', 'QUEUE', 'RETURN',
      REJECT', 'DNAT', 'SNAT', 'LOG', 'MASQUERADE', 'REDIRECT'.
      Default value is 'ACCEPT'"
    newvalues(:ACCEPT, :DROP, :QUEUE, :RETURN, :REJECT, :DNAT, :SNAT, :LOG,
              :MASQUERADE, :REDIRECT)
    defaultto "ACCEPT"
  end

  newproperty(:source, :array_matching => :all) do
    desc "The value for the iptables --source parameter.
      Accepts a single string or array."

    def should_to_s(value)
      value = [value] unless value.is_a?(Array)
      value.join(',')
    end
  end

  newproperty(:destination, :array_matching => :all) do
    desc "The value for the iptables --destination parameter.
      Accepts a single string or array."

    def should_to_s(value)
      value = [value] unless value.is_a?(Array)
      value.join(',')
    end
  end

  newproperty(:sport, :array_matching => :all) do
    desc "The value for the iptables --source-port parameter.
      If an array is specified, values will be passed to multiport module."

    munge do |value|
      @resource.string_to_port(value)
    end

    def should_to_s(value)
      value = [value] unless value.is_a?(Array)
      value.join(',')
    end
  end

  newproperty(:dport, :array_matching => :all) do
    desc "The value for the iptables --destination-port parameter.
      If an array is specified, values will be passed to multiport module."
    
    munge do |value|
      @resource.string_to_port(value)
    end

    def should_to_s(value)
      value = [value] unless value.is_a?(Array)
      value.join(',')
    end
  end

  newproperty(:iniface) do
    desc "The value for the iptables --in-interface parameter"
  end

  newproperty(:outiface) do
    desc "The value for the iptables --out-interface parameter"
  end

  newproperty(:tosource) do
    desc "The value for the iptables --to-source parameter"
  end

  newproperty(:todest) do
    desc "The value for the iptables --to-destination parameter"
  end

  newproperty(:toports) do
    desc "The value for the iptables --to-ports parameter"
  end

  newproperty(:reject) do
    desc "The value for the iptables --reject-with parameter"
  end

  newproperty(:log_level) do
    desc "The value for the iptables --log-level parameter"
  end

  newproperty(:log_prefix) do
    desc "The value for the iptables --log-level parameter"
  end

  newproperty(:icmp) do
    desc "The value for the iptables --icmp-type parameter"

    munge do |value|
      if value.kind_of?(String)
        value = @resource.icmp_name_to_number(value)
      else
        value
      end

      if value == nil && value != ""
        self.fail("cannot work out icmp type")
      end
      value
    end
  end

  newproperty(:state, :array_matching => :all) do
    desc "The value for the iptables -m state --state parameter.
      Possible values are: 'INVALID', 'ESTABLISHED', 'NEW', 'RELATED'.
      Accepts a single string or array."

    def should_to_s(value)
      value = [value] unless value.is_a?(Array)
      value.join(',')
    end
  end

  newproperty(:limit) do
    desc "The value for the iptables -m limit --limit parameter.
      Example values are: '50/sec', '40/min', '30/hour', '10/day'."
  end

  newproperty(:burst) do
    desc "The value for the iptables --limit-burst parameter."

    validate do |value|
      if value.to_s !~ /^[0-9]+$/
        self.fail "burst accepts only numeric values"
      end
    end
  end
  
  validate do
    debug("[validate]")

    # TODO: this is put here to skip validation if ensure is not set. This
    # is because there is a revalidation stage called later where the values
    # are not set correctly. I tried tracing it - but have put in this
    # workaround instead to skip. Must get to the bottom of this.
    if ! value(:ensure)
      return
    end

    # First we make sure the chains and tables are valid combinations
    if value(:table).to_s == "filter" && value(:chain) =~ /PREROUTING|POSTROUTING/
      self.fail "PREROUTING and POSTROUTING cannot be used in table 'filter'"
    end

    if value(:table).to_s == "nat" && value(:chain) =~ /INPUT|FORWARD/
      self.fail "INPUT and FORWARD cannot be used in table 'nat'"
    end

    if value(:table).to_s == "raw" && value(:chain) =~ /INPUT|FORWARD|POSTROUTING/
      self.fail "INPUT, FORWARD and POSTROUTING cannot be used in table raw"
    end

    # Now we analyse the individual properties to make sure they apply to
    # the correct combinations.
    if value(:iniface)
      unless value(:chain).to_s =~ /INPUT|FORWARD|PREROUTING/
        self.fail "Parameter iniface only applies to chains " \
          "INPUT,FORWARD,PREROUTING"
      end
    end

    if value(:outiface)
      unless value(:chain).to_s =~ /OUTPUT|FORWARD|PREROUTING/
        self.fail "Parameter outiface only applies to chains " \
          "OUTPUT,FORWARD,PREROUTING"
      end
    end

    if value(:dport)
      unless value(:proto).to_s =~ /tcp|udp|sctp/
        self.fail "[%s] Parameter dport only applies to sctp, tcp and udp " \
          "protocols. Current protocol is [%s] and dport is [%s]" %
          [value(:name), should(:proto), should(:dport)]
      end
    end

    if value(:jump).to_s == "DNAT"
      unless value(:table).to_s =~ /nat/
        self.fail "Parameter jump => DNAT only applies to table => nat"
      end

      unless value(:todest)
        self.fail "Parameter jump => DNAT must have todest parameter"
      end
    end

    if value(:jump).to_s == "SNAT"
      unless value(:table).to_s =~ /nat/
        self.fail "Parameter jump => SNAT only applies to table => nat"
      end

      unless value(:tosource)
        self.fail "Parameter jump => DNAT must have tosource parameter"
      end
    end

    if value(:jump).to_s == "REDIRECT"
      unless value(:toports)
        self.fail "Parameter jump => REDIRECT missing mandatory toports " \
          "parameter"
      end
    end

    if value(:jump).to_s == "MASQUERADE"
      unless value(:table).to_s =~ /nat/
        self.fail "Parameter jump => MASQUERADE only applies to table => nat"
      end
    end

    if value(:burst) && ! value(:limit)
      self.fail "burst makes no sense without limit"
    end
  end
end
