# See: #10295 for more details.
#
# This is a workaround for bug: #4248 whereby ruby files outside of the normal
# provider/type path do not load until pluginsync has occured on the puppetmaster
#
# In this case I'm trying the relative path first, then falling back to normal
# mechanisms. This should be fixed in future versions of puppet but it looks
# like we'll need to maintain this for some time perhaps.
$LOAD_PATH.unshift(File.join(File.dirname(__FILE__),"..",".."))
require 'puppet/util/firewall'

Puppet::Type.newtype(:firewall) do
  include Puppet::Util::Firewall

  @doc = <<-EOS
    This type provides the capability to manage firewall rules within
    puppet.
  EOS

  feature :rate_limiting, "Rate limiting features."
  feature :snat, "Source NATing"
  feature :dnat, "Destination NATing"
  feature :interface_match, "Interface matching"
  feature :icmp_match, "Matching ICMP types"
  feature :owner, "Matching owners"
  feature :state_match, "Matching stateful firewall states"
  feature :reject_type, "The ability to control reject messages"
  feature :log_level, "The ability to control the log level"
  feature :log_prefix, "The ability to add prefixes to log messages"

  # provider specific features
  feature :iptables, "The provider provides iptables features."

  ensurable do
    desc <<-EOS
      Manage the state of this rule. The default action is *present*.
    EOS

    newvalue(:present) do
      provider.insert
    end

    newvalue(:absent) do
      provider.delete
    end

    defaultto :present
  end

  newparam(:name) do
    desc <<-EOS
      The canonical name of the rule. This name is also used for ordering
      so make sure you prefix the rule with a number:

          000 this runs first
          999 this runs last

      Depending on the provider, the name of the rule can be stored using
      the comment feature of the underlying firewall subsystem.
    EOS
    isnamevar

    # Keep rule names simple - they must start with a number
    newvalues(/^\d+[[:alpha:][:digit:][:punct:][:space:]]+$/)
  end

  newproperty(:action) do
    desc <<-EOS
      This is the action to perform on a match. Can be one of:

      * accept - the packet is accepted
      * reject - the packet is rejected with a suitable ICMP response
      * drop - the packet is dropped

      If you specify no value it will simply match the rule but perform no
      action unless you provide a provider specific parameter (such as *jump*).
    EOS
    newvalues(:accept, :reject, :drop)
  end

  # Generic matching properties
  newproperty(:source) do
    desc <<-EOS
      An array of source addresses. For example:

          source => '192.168.2.0/24'

      The source can also be an IPv6 address if your provider supports it.
    EOS

    munge do |value|
      @resource.host_to_ip(value)
    end
  end

  newproperty(:destination) do
    desc <<-EOS
      An array of destination addresses to match. For example:

          destination => '192.168.1.0/24'

      The destination can also be an IPv6 address if your provider supports it.
    EOS

    munge do |value|
      @resource.host_to_ip(value)
    end
  end

  newproperty(:sport, :array_matching => :all) do
    desc <<-EOS
      The source port to match for this filter (if the protocol supports
      ports). Will accept a single element or an array.

      For some firewall providers you can pass a range of ports in the format:

          <start_number>-<ending_number>

      For example:

          1-1024

      This would cover ports 1 to 1024.
    EOS

    munge do |value|
      @resource.string_to_port(value)
    end

    def should_to_s(value)
      value = [value] unless value.is_a?(Array)
      value.join(',')
    end
  end

  newproperty(:dport, :array_matching => :all) do
    desc <<-EOS
      The destination port to match for this filter (if the protocol supports
      ports). Will accept a single element or an array.

      For some firewall providers you can pass a range of ports in the format:

          <start_number>-<ending_number>

      For example:

          1-1024

      This would cover ports 1 to 1024.
    EOS

    munge do |value|
      @resource.string_to_port(value)
    end

    def should_to_s(value)
      value = [value] unless value.is_a?(Array)
      value.join(',')
    end
  end

  newproperty(:port, :array_matching => :all) do
    desc <<-EOS
      The destination or source port to match for this filter (if the protocol
      supports ports). Will accept a single element or an array.

      For some firewall providers you can pass a range of ports in the format:

          <start_number>-<ending_number>

      For example:

          1-1024

      This would cover ports 1 to 1024.
    EOS

    munge do |value|
      @resource.string_to_port(value)
    end

    def should_to_s(value)
      value = [value] unless value.is_a?(Array)
      value.join(',')
    end
  end

  newproperty(:proto) do
    desc <<-EOS
      The specific protocol to match for this rule. By default this is
      *tcp*.
    EOS

    newvalues(:tcp, :udp, :icmp, :"ipv6-icmp", :esp, :ah, :vrrp, :igmp, :ipencap, :all)
    defaultto "tcp"
  end

  # Iptables specific
  newproperty(:chain, :required_features => :iptables) do
    desc <<-EOS
      Name of the chain to use. Can be one of the built-ins:

      * INPUT
      * FORWARD
      * OUTPUT
      * PREROUTING
      * POSTROUTING

      Or you can provide a user-based chain.

      The default value is 'INPUT'.
    EOS

    defaultto "INPUT"
    newvalue(/^[a-zA-Z0-9\-_]+$/)
  end

  newproperty(:table, :required_features => :iptables) do
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
    defaultto "filter"
  end

  newproperty(:jump, :required_features => :iptables) do
    desc <<-EOS
      The value for the iptables --jump parameter. Normal values are:

      * QUEUE
      * RETURN
      * DNAT
      * SNAT
      * LOG
      * MASQUERADE
      * REDIRECT

      But any valid chain name is allowed.

      For the values ACCEPT, DROP and REJECT you must use the generic
      'action' parameter. This is to enfore the use of generic parameters where
      possible for maximum cross-platform modelling.

      If you set both 'accept' and 'jump' parameters, you will get an error as
      only one of the options should be set.
    EOS

    validate do |value|
      unless value =~ /^[a-zA-Z0-9\-_]+$/
        raise ArgumentError, <<-EOS
          Jump destination must consist of alphanumeric characters, an
          underscore or a yphen.
        EOS
      end

      if ["accept","reject","drop"].include?(value.downcase)
        raise ArgumentError, <<-EOS
          Jump destination should not be one of ACCEPT, REJECT or DENY. Use
          the action property instead.
        EOS
      end

    end
  end

  # Interface specific matching properties
  newproperty(:iniface, :required_features => :interface_match) do
    desc <<-EOS
      Input interface to filter on.
    EOS
    newvalues(/^[a-zA-Z0-9\-_]+$/)
  end

  newproperty(:outiface, :required_features => :interface_match) do
    desc <<-EOS
      Output interface to filter on.
    EOS
    newvalues(/^[a-zA-Z0-9\-_]+$/)
  end

  # NAT specific properties
  newproperty(:tosource, :required_features => :snat) do
    desc <<-EOS
      When using jump => "SNAT" you can specify the new source address using
      this parameter.
    EOS
  end

  newproperty(:todest, :required_features => :dnat) do
    desc <<-EOS
      When using jump => "DNAT" you can specify the new destination address
      using this paramter.
    EOS
  end

  newproperty(:toports, :required_features => :dnat) do
    desc <<-EOS
      For DNAT this is the port that will replace the destination port.
    EOS
  end

  # Reject ICMP type
  newproperty(:reject, :required_features => :reject_type) do
    desc <<-EOS
      When combined with jump => "REJECT" you can specify a different icmp
      response to be sent back to the packet sender.
    EOS
  end

  # Logging properties
  newproperty(:log_level, :required_features => :log_level) do
    desc <<-EOS
      When combined with jump => "LOG" specifies the system log level to log
      to.
    EOS

    munge do |value|
      if value.kind_of?(String)
        value = @resource.log_level_name_to_number(value)
      else
        value
      end

      if value == nil && value != ""
        self.fail("Unable to determine log level")
      end
      value
    end
  end

  newproperty(:log_prefix, :required_features => :log_prefix) do
    desc <<-EOS
      When combined with jump => "LOG" specifies the log prefix to use when
      logging.
    EOS
  end

  # ICMP matching property
  newproperty(:icmp, :required_features => :icmp_match) do
    desc <<-EOS
      When matching ICMP packets, this is the type of ICMP packet to match.
    EOS

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

  newproperty(:state, :array_matching => :all, :required_features =>
    :state_match) do

    desc <<-EOS
      Matches a packet based on its state in the firewall stateful inspection
      table. Values can be:

      * INVALID
      * ESTABLISHED
      * NEW
      * RELATED
    EOS

    newvalues(:INVALID,:ESTABLISHED,:NEW,:RELATED)

    # States should always be sorted. This normalizes the resource states to
    # keep it consistent with the sorted result from iptables-save.
    def should=(values)
      @should = super(values).sort
    end

    def should_to_s(value)
      value = [value] unless value.is_a?(Array)
      value.join(',')
    end
  end

  # Rate limiting properties
  newproperty(:limit, :required_features => :rate_limiting) do
    desc <<-EOS
      Rate limiting value for matched packets. The format is:
      rate/[/second/|/minute|/hour|/day].

      Example values are: '50/sec', '40/min', '30/hour', '10/day'."
    EOS
  end

  newproperty(:burst, :required_features => :rate_limiting) do
    desc <<-EOS
      Rate limiting burst value (per second) before limit checks apply.
    EOS
    newvalue(/^\d+$/)
  end

  newproperty(:uid, :array_matching =>:all, :required_features => :owner) do
    desc <<-EOS
      UID or Username owner matching rule.  Accepts a string argument
      only, as iptables does not accept multiple uid in a single
      statement.
    EOS
  end

  newproperty(:gid, :array_matching =>:all, :required_features => :owner) do
    desc <<-EOS
      GID or Group owner matching rule.  Accepts a string argument
      only, as iptables does not accept multiple gid in a single
      statement.
    EOS
  end

  newparam(:line) do
    desc <<-EOS
      Read-only property for caching the rule line.
    EOS
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
    if value(:table).to_s == "filter" &&
      value(:chain) =~ /PREROUTING|POSTROUTING/

      self.fail "PREROUTING and POSTROUTING cannot be used in table 'filter'"
    end

    if value(:table).to_s == "nat" && value(:chain) =~ /INPUT|FORWARD/
      self.fail "INPUT and FORWARD cannot be used in table 'nat'"
    end

    if value(:table).to_s == "raw" &&
      value(:chain) =~ /INPUT|FORWARD|POSTROUTING/

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

    if value(:uid)
      unless value(:chain).to_s =~ /OUTPUT|POSTROUTING/
        self.fail "Parameter uid only applies to chains " \
          "OUTPUT,POSTROUTING"
      end
    end

    if value(:gid)
      unless value(:chain).to_s =~ /OUTPUT|POSTROUTING/
        self.fail "Parameter gid only applies to chains " \
          "OUTPUT,POSTROUTING"
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

    if value(:action) && value(:jump)
      self.fail "Only one of the parameters 'action' and 'jump' can be set"
    end
  end
end
