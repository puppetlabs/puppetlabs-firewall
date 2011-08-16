# Puppet Firewall type
require 'puppet/util/firewall'

Puppet::Type.newtype(:firewall) do
  include Puppet::Util::Firewall

  @doc = "This type provides the capability to manage firewall rules within 
          puppet."

  feature :rate_limiting, "Rate limiting features."
  feature :snat, "Source NATing"
  feature :dnat, "Destination NATing"
  feature :interface_match, "Interface matching"
  feature :icmp_match, "Matching ICMP types"
  feature :state_match, "Matching stateful firewall states"
  feature :reject_type, "The ability to control reject messages"
  feature :log_level, "The ability to control the log level"
  feature :log_prefix, "The ability to add prefixes to log messages"

  # provider specific features
  feature :iptables, "The provider provides iptables features."

  ensurable do
    desc "Manage the state of this rule."

    newvalue(:present) do
      provider.insert
    end

    newvalue(:absent) do
      provider.delete
    end

    defaultto :present
  end

  newparam(:name) do
    desc "The canonical name of the rule."
    isnamevar

    # Keep rule names simple - they must start with a number
    newvalues(/^\d+[a-zA-Z0-9\s\-_]+$/)
  end

  newparam(:action) do
    desc "Action to perform on this rule."
    newvalues(:accept, :reject, :drop)
    defaultto :accept
  end

  # Generic matching properties
  newproperty(:source) do
    desc "The source IP address to match."
  end

  newproperty(:destination) do
    desc "The destination IP address to match."
  end

  newproperty(:sport, :array_matching => :all) do
    desc "The source port to match for this filter (if the protocol supports 
          ports). Will accept a single element or an array."

    munge do |value|
      @resource.string_to_port(value)
    end

    def should_to_s(value)
      value = [value] unless value.is_a?(Array)
      value.join(',')
    end
  end

  newproperty(:dport, :array_matching => :all) do
    desc "The destination port to match for this filter (if the protocol 
          supports ports). Will accept a single element or an array."
    
    munge do |value|
      @resource.string_to_port(value)
    end

    def should_to_s(value)
      value = [value] unless value.is_a?(Array)
      value.join(',')
    end
  end

  newproperty(:proto) do
    desc "The specific protocol to match for this rule."
    newvalues(:tcp, :udp, :icmp, :"ipv6-icmp", :esp, :ah, :vrrp, :igmp, :all)
    defaultto "tcp"
  end

  # Iptables specific
  newproperty(:chain, :required_features => :iptables) do
    desc "The value for the iptables -A parameter. Normal values are: 'INPUT', 
          'FORWARD', 'OUTPUT', 'PREROUTING', 'POSTROUTING' but you can also
          specify a user created chain."

    defaultto "INPUT"
    newvalue(/^[a-zA-Z0-9\-_]+$/)
  end

  newproperty(:table, :required_features => :iptables) do
    desc "The value for the iptables -t parameter."
    newvalues(:nat, :mangle, :filter, :raw, :rawpost)
    defaultto "filter"
  end

  newproperty(:jump, :required_features => :iptables) do
    desc "The value for the iptables --jump parameter. Normal values are: 
          'ACCEPT', 'DROP', 'QUEUE', 'RETURN', REJECT', 'DNAT', 'SNAT', 'LOG', 
          'MASQUERADE', 'REDIRECT'. But any valid chain name is allowed."
    newvalues(/^[a-zA-Z0-9\-_]+$/)
    defaultto "ACCEPT"
  end

  # Interface specific matching properties
  newproperty(:iniface, :required_features => :interface_match) do
    desc "Match input interface."
    newvalues(/^[a-zA-Z0-9\-_]+$/)
  end

  newproperty(:outiface, :required_features => :interface_match) do
    desc "Match ouput interface."
    newvalues(/^[a-zA-Z0-9\-_]+$/)
  end

  # NAT specific properties
  newproperty(:tosource, :required_features => :snat) do
    desc "For SNAT this is the IP address that will replace the source IP 
          address."
  end

  newproperty(:todest, :required_features => :dnat) do
    desc "For DNAT this is the IP address that will replace the destination IP 
          address."
  end

  newproperty(:toports, :required_features => :dnat) do
    desc "For DNAT this is the port that will replace the destination port."
  end

  # Reject ICMP type
  newproperty(:reject, :required_features => :reject_type) do
    desc "The ICMP response to reject a packet with."
  end

  # Logging properties
  newproperty(:log_level, :required_features => :log_level) do
    desc "The syslog level to log to."
  end

  newproperty(:log_prefix, :required_features => :log_prefix) do
    desc "The syslog prefix."
  end

  # ICMP matching property
  newproperty(:icmp, :required_features => :icmp_match) do
    desc "When matching ICMP packets, this is the type of ICMP packet to match."

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

  newproperty(:state, :array_matching => :all, :required_features => :state_match) do
    desc "Matches a packet based on its state in the firewall stateful inspection 
          table."

    newvalues(:INVALID,:ESTABLISHED,:NEW,:RELATED)

    def should_to_s(value)
      value = [value] unless value.is_a?(Array)
      value.join(',')
    end
  end

  # Rate limiting properties
  newproperty(:limit, :required_features => :rate_limiting) do
    desc "Rate limiting value. Example values are: '50/sec', '40/min', 
          '30/hour', '10/day'."
  end

  newproperty(:burst, :required_features => :rate_limiting) do
    desc "Rate limiting burst value (per second)."
    newvalue(/^\d+$/)
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
      unless value(:chain).to_s =~ /OUTPUT|FORWARD|POSTROUTING/
        self.fail "Parameter outiface only applies to chains " \
          "OUTPUT,FORWARD,POSTROUTING"
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
