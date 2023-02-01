# frozen_string_literal: true

# See: #10295 for more details.
#
# This is a workaround for bug: #4248 whereby ruby files outside of the normal
# provider/type path do not load until pluginsync has occured on the puppet server
#
# In this case I'm trying the relative path first, then falling back to normal
# mechanisms. This should be fixed in future versions of puppet but it looks
# like we'll need to maintain this for some time perhaps.
$LOAD_PATH.unshift(File.join(File.dirname(__FILE__), '..', '..'))
require 'puppet/util/firewall'

Puppet::Type.newtype(:firewall) do
  include Puppet::Util::Firewall

  @doc = <<-PUPPETCODE
    @summary
      This type provides the capability to manage firewall rules within puppet.

    **Autorequires:**

    If Puppet is managing the iptables or ip6tables chains specified in the
    `chain` or `jump` parameters, the firewall resource will autorequire
    those firewallchain resources.

    If Puppet is managing the iptables, iptables-persistent, or iptables-services packages,
    and the provider is iptables or ip6tables, the firewall resource will
    autorequire those packages to ensure that any required binaries are
    installed.

    #### Providers
      Note: Not all features are available with all providers.

      * ip6tables: Ip6tables type provider

        * Required binaries: ip6tables-save, ip6tables.
        * Supported features: address_type, connection_limiting, conntrack, dnat, hop_limiting, icmp_match,
        interface_match, iprange, ipsec_dir, ipsec_policy, ipset, iptables, isfirstfrag,
        ishasmorefrags, islastfrag, length, log_level, log_prefix, log_uid,
        log_tcp_sequence, log_tcp_options, log_ip_options, mask, mss,
        owner, pkttype, queue_bypass, queue_num, rate_limiting, recent_limiting, reject_type,
        snat, socket, state_match, string_matching, tcp_flags, hashlimit, bpf.

      * iptables: Iptables type provider

        * Required binaries: iptables-save, iptables.
        * Default for kernel == linux.
        * Supported features: address_type, clusterip, connection_limiting, conntrack, dnat, icmp_match,
        interface_match, iprange, ipsec_dir, ipsec_policy, ipset, iptables, isfragment, length,
        log_level, log_prefix, log_uid, log_tcp_sequence, log_tcp_options, log_ip_options,
        mark, mask, mss, netmap, nflog_group, nflog_prefix,
        nflog_range, nflog_threshold, owner, pkttype, queue_bypass, queue_num, rate_limiting,
        recent_limiting, reject_type, snat, socket, state_match, string_matching, tcp_flags, bpf.

    #### Features
      * address_type: The ability to match on source or destination address type.

      * clusterip: Configure a simple cluster of nodes that share a certain IP and MAC address without an explicit load balancer in front of them.

      * condition: Match if a specific condition variable is (un)set (requires xtables-addons)

      * connection_limiting: Connection limiting features.

      * conntrack: Connection tracking features.

      * dnat: Destination NATing.

      * hop_limiting: Hop limiting features.

      * icmp_match: The ability to match ICMP types.

      * interface_match: Interface matching.

      * iprange: The ability to match on source or destination IP range.

      * ipsec_dir: The ability to match IPsec policy direction.

      * ipsec_policy: The ability to match IPsec policy.

      * iptables: The provider provides iptables features.

      * isfirstfrag: The ability to match the first fragment of a fragmented ipv6 packet.

      * isfragment: The ability to match fragments.

      * ishasmorefrags: The ability to match a non-last fragment of a fragmented ipv6 packet.

      * islastfrag: The ability to match the last fragment of an ipv6 packet.

      * length: The ability to match the length of the layer-3 payload.

      * log_level: The ability to control the log level.

      * log_prefix: The ability to add prefixes to log messages.

      * log_uid: The ability to log the userid of the process which generated the packet.

      * log_tcp_sequence: The ability to log TCP sequence numbers.

      * log_tcp_options: The ability to log TCP packet header.

      * log_ip_options: The ability to log IP/IPv6 packet header.

      * mark: The ability to match or set the netfilter mark value associated with the packet.

      * mask: The ability to match recent rules based on the ipv4 mask.

      * nflog_group: The ability to set the group number for NFLOG.

      * nflog_prefix: The ability to set a prefix for nflog messages.

      * nflog_size: Set the max size of a message to send to nflog.

      * nflog_threshold: The ability to set nflog_threshold.

      * owner: The ability to match owners.

      * pkttype: The ability to match a packet type.

      * rate_limiting: Rate limiting features.

      * recent_limiting: The netfilter recent module.

      * reject_type: The ability to control reject messages.

      * set_mss: Set the TCP MSS of a packet.

      * snat: Source NATing.

      * socket: The ability to match open sockets.

      * state_match: The ability to match stateful firewall states.

      * string_matching: The ability to match a given string by using some pattern matching strategy.

      * tcp_flags: The ability to match on particular TCP flag settings.

      * netmap: The ability to map entire subnets via source or destination nat rules.

      * hashlimit: The ability to use the hashlimit-module.

      * bpf: The ability to use Berkeley Paket Filter rules.

      * ipvs: The ability to match IP Virtual Server packets.

      * ct_target: The ability to set connection tracking parameters for a packet or its associated connection.

      * random_fully: The ability to use --random-fully flag.
  PUPPETCODE

  feature :connection_limiting, 'Connection limiting features.'
  feature :condition, 'Match if a specific condition variable is (un)set.'
  feature :conntrack, 'Connection tracking features.'
  feature :hop_limiting, 'Hop limiting features.'
  feature :rate_limiting, 'Rate limiting features.'
  feature :recent_limiting, 'The netfilter recent module'
  feature :snat, 'Source NATing'
  feature :dnat, 'Destination NATing'
  feature :netmap, 'NET MAPping'
  feature :interface_match, 'Interface matching'
  feature :icmp_match, 'Matching ICMP types'
  feature :owner, 'Matching owners'
  feature :state_match, 'Matching stateful firewall states'
  feature :reject_type, 'The ability to control reject messages'
  feature :log_level, 'The ability to control the log level'
  feature :log_prefix, 'The ability to add prefixes to log messages'
  feature :log_uid, 'Add UIDs to log messages'
  feature :log_tcp_sequence, 'Add TCP sequence numbers to log messages'
  feature :log_tcp_options, 'Add TCP packet header to log messages'
  feature :log_ip_options, 'Add IP/IPv6 packet header to log messages'
  feature :mark, 'Match or Set the netfilter mark value associated with the packet'
  feature :mss, 'Match a given TCP MSS value or range.'
  feature :tcp_flags, 'The ability to match on particular TCP flag settings'
  feature :pkttype, 'Match a packet type'
  feature :rpfilter, 'Perform reverse-path filtering'
  feature :socket, 'Match open sockets'
  feature :isfragment, 'Match fragments'
  feature :address_type, 'The ability match on source or destination address type'
  feature :iprange, 'The ability match on source or destination IP range '
  feature :ishasmorefrags, 'Match a non-last fragment of a fragmented ipv6 packet - might be first'
  feature :islastfrag, 'Match the last fragment of an ipv6 packet'
  feature :isfirstfrag, 'Match the first fragment of a fragmented ipv6 packet'
  feature :ipsec_policy, 'Match IPsec policy'
  feature :ipsec_dir, 'Match IPsec policy direction'
  feature :mask, 'Ability to match recent rules based on the ipv4 mask'
  feature :nflog_group, 'netlink group to subscribe to for logging'
  feature :nflog_prefix, ''
  feature :nflog_range, ''
  feature :nflog_size, ''
  feature :nflog_threshold, ''
  feature :ipset, 'Match against specified ipset list'
  feature :clusterip, 'Configure a simple cluster of nodes that share a certain IP and MAC address without an explicit load balancer in front of them.'
  feature :length, 'Match the length of layer-3 payload'
  feature :string_matching, 'String matching features'
  feature :queue_num, 'Which NFQUEUE to send packets to'
  feature :queue_bypass, 'If nothing is listening on queue_num, allow packets to bypass the queue'
  feature :hashlimit, 'Hashlimit features'
  feature :bpf, 'Berkeley Paket Filter feature'
  feature :ipvs, 'Packet belongs to an IP Virtual Server connection'
  feature :ct_target, 'The ability to set connection tracking parameters for a packet or its associated connection'
  feature :random_fully, 'The ability to use --random-fully flag'
  # provider specific features
  feature :iptables, 'The provider provides iptables features.'

  ensurable do
    desc <<-PUPPETCODE
      Manage the state of this rule.
    PUPPETCODE

    newvalue(:present) do
      provider.insert
    end

    newvalue(:absent) do
      provider.delete
    end

    defaultto :present
  end

  newparam(:name) do
    desc <<-PUPPETCODE
      The canonical name of the rule. This name is also used for ordering
      so make sure you prefix the rule with a number:

          000 this runs first
          999 this runs last

      Depending on the provider, the name of the rule can be stored using
      the comment feature of the underlying firewall subsystem.
    PUPPETCODE
    isnamevar

    # Keep rule names simple - they must start with a number
    newvalues(%r{^\d+[[:graph:][:space:]]+$})
  end

  newparam(:onduplicaterulebehaviour) do
    desc <<-PUPPETCODE
      In certain situations it is possible for an unmanaged rule to exist
      on the target system that has the same comment as the rule
      specified in the manifest.

      This setting determines what happens when such a duplicate is found.

      It offers three options:

        * ignore - The duplicate rule is ignored and any updates to the resource will continue unaffected.
        * warn - The duplicate rule is logged as a warning and any updates to the resource will continue unaffected.
        * error - The duplicate rule is logged as an error and any updates to the resource will be skipped.
    PUPPETCODE
    newvalues(:ignore, :warn, :error)
    defaultto :warn
  end

  newproperty(:action) do
    desc <<-PUPPETCODE
      This is the action to perform on a match. Can be one of:

      * accept - the packet is accepted
      * reject - the packet is rejected with a suitable ICMP response
      * drop - the packet is dropped

      If you specify no value it will simply match the rule but perform no
      action unless you provide a provider specific parameter (such as *jump*).
    PUPPETCODE
    newvalues(:accept, :reject, :drop)
  end

  # Generic matching properties
  newproperty(:source) do
    desc <<-PUPPETCODE
      The source address. For example:

          source => '192.168.2.0/24'

      You can also negate a mask by putting ! in front. For example:

          source => '! 192.168.2.0/24'

      The source can also be an IPv6 address if your provider supports it.
    PUPPETCODE

    munge do |value|
      case @resource[:provider]
      when :iptables
        protocol = :IPv4
      when :ip6tables
        protocol = :IPv6
      else
        raise('cannot work out protocol family')
      end

      begin
        @resource.host_to_mask(value, protocol)
      rescue StandardError => e
        raise("host_to_ip failed for #{value}, exception #{e}")
      end
    end
  end

  # Source IP range
  newproperty(:src_range, required_features: :iprange) do
    desc <<-PUPPETCODE
      The source IP range. For example:

          src_range => '192.168.1.1-192.168.1.10'

      The source IP range must be in 'IP1-IP2' format.
    PUPPETCODE

    validate do |value|
      matches = %r{^([^\-\/]+)-([^\-\/]+)$}.match(value)
      raise(ArgumentError, "The source IP range must be in 'IP1-IP2' format.") unless matches
      start_addr = matches[1]
      end_addr = matches[2]

      [start_addr, end_addr].each do |addr|
        begin # rubocop:disable Style/RedundantBegin
          @resource.host_to_ip(addr)
        rescue StandardError
          raise("Invalid IP address \"#{addr}\" in range \"#{value}\"")
        end
      end
    end
  end

  newproperty(:destination) do
    desc <<-PUPPETCODE
      The destination address to match. For example:

          destination => '192.168.1.0/24'

      You can also negate a mask by putting ! in front. For example:

          destination  => '! 192.168.2.0/24'

      The destination can also be an IPv6 address if your provider supports it.
    PUPPETCODE

    munge do |value|
      case @resource[:provider]
      when :iptables
        protocol = :IPv4
      when :ip6tables
        protocol = :IPv6
      else
        raise('cannot work out protocol family')
      end

      begin
        @resource.host_to_mask(value, protocol)
      rescue StandardError => e
        raise("host_to_ip failed for #{value}, exception #{e}")
      end
    end
  end

  # Destination IP range
  newproperty(:dst_range, required_features: :iprange) do
    desc <<-PUPPETCODE
      The destination IP range. For example:

          dst_range => '192.168.1.1-192.168.1.10'

      The destination IP range must be in 'IP1-IP2' format.
    PUPPETCODE

    validate do |value|
      matches = %r{^([^\-\/]+)-([^\-\/]+)$}.match(value)
      raise(ArgumentError, "The destination IP range must be in 'IP1-IP2' format.") unless matches
      start_addr = matches[1]
      end_addr = matches[2]

      [start_addr, end_addr].each do |addr|
        begin # rubocop:disable Style/RedundantBegin
          @resource.host_to_ip(addr)
        rescue StandardError
          raise("Invalid IP address \"#{addr}\" in range \"#{value}\"")
        end
      end
    end
  end

  newproperty(:proto) do
    desc <<-PUPPETCODE
      The specific protocol to match for this rule.
    PUPPETCODE

    newvalues(*[:ip, :tcp, :udp, :icmp, :"ipv6-icmp", :esp, :ah, :vrrp, :carp, :igmp, :ipencap, :ipv4, :ipv6, :ospf, :gre, :cbt, :sctp, :pim, :all].map { |proto|
      [proto, "! #{proto}".to_sym]
    }.flatten)
    defaultto 'tcp'
  end

  newproperty(:sport, array_matching: :all) do
    desc <<-PUPPETCODE
      The source port to match for this filter (if the protocol supports
      ports). Will accept a single element or an array.

      For some firewall providers you can pass a range of ports in the format:

          <start_number>-<ending_number>

      For example:

          1-1024

      This would cover ports 1 to 1024.
    PUPPETCODE

    munge do |value|
      @resource.string_to_port(value, @resource[:proto])
    end

    def to_s?(value)
      should_to_s(value)
    end

    def should_to_s(value)
      value = [value] unless value.is_a?(Array)
      value.join(',')
    end
  end

  newproperty(:dport, array_matching: :all) do
    desc <<-PUPPETCODE
      The destination port to match for this filter (if the protocol supports
      ports). Will accept a single element or an array.

      For some firewall providers you can pass a range of ports in the format:

          <start_number>-<ending_number>

      For example:

          1-1024

      This would cover ports 1 to 1024.
    PUPPETCODE

    munge do |value|
      @resource.string_to_port(value, @resource[:proto])
    end

    def to_s?(value)
      should_to_s(value)
    end

    def should_to_s(value)
      value = [value] unless value.is_a?(Array)
      value.join(',')
    end
  end

  newproperty(:port, array_matching: :all) do
    desc <<-PUPPETCODE
      *note* This property has been DEPRECATED

      The destination or source port to match for this filter (if the protocol
      supports ports). Will accept a single element or an array.

      For some firewall providers you can pass a range of ports in the format:

          <start_number>-<ending_number>

      For example:

          1-1024

      This would cover ports 1 to 1024.
    PUPPETCODE

    validate do |_value|
      Puppet.warning('Passing port to firewall is deprecated and will be removed. Use dport and/or sport instead.')
    end

    munge do |value|
      @resource.string_to_port(value, @resource[:proto])
    end

    def to_s?(value)
      should_to_s(value)
    end

    def should_to_s(value)
      value = [value] unless value.is_a?(Array)
      value.join(',')
    end
  end

  newproperty(:dst_type, required_features: :address_type, array_matching: :all) do
    desc <<-PUPPETCODE
      The destination address type. For example:

          dst_type => ['LOCAL']

      Can be one of:

      * UNSPEC - an unspecified address
      * UNICAST - a unicast address
      * LOCAL - a local address
      * BROADCAST - a broadcast address
      * ANYCAST - an anycast packet
      * MULTICAST - a multicast address
      * BLACKHOLE - a blackhole address
      * UNREACHABLE - an unreachable address
      * PROHIBIT - a prohibited address
      * THROW - undocumented
      * NAT - undocumented
      * XRESOLVE - undocumented

      In addition, it accepts '--limit-iface-in' and '--limit-iface-out' flags, specified as:

          dst_type => ['LOCAL --limit-iface-in']

      It can also be negated using '!':

          dst_type => ['! LOCAL']

      Will accept a single element or an array.
    PUPPETCODE

    newvalues(*[:UNSPEC, :UNICAST, :LOCAL, :BROADCAST, :ANYCAST, :MULTICAST,
                :BLACKHOLE, :UNREACHABLE, :PROHIBIT, :THROW, :NAT, :XRESOLVE].map { |address_type|
                [
                  address_type,
                  "! #{address_type}".to_sym,
                  "#{address_type} --limit-iface-in".to_sym,
                  "#{address_type} --limit-iface-out".to_sym,
                  "! #{address_type} --limit-iface-in".to_sym,
                  "! #{address_type} --limit-iface-out".to_sym,
                ]
              }.flatten)
  end

  newproperty(:src_type, required_features: :address_type, array_matching: :all) do
    desc <<-PUPPETCODE
      The source address type. For example:

          src_type => ['LOCAL']

      Can be one of:

      * UNSPEC - an unspecified address
      * UNICAST - a unicast address
      * LOCAL - a local address
      * BROADCAST - a broadcast address
      * ANYCAST - an anycast packet
      * MULTICAST - a multicast address
      * BLACKHOLE - a blackhole address
      * UNREACHABLE - an unreachable address
      * PROHIBIT - a prohibited address
      * THROW - undocumented
      * NAT - undocumented
      * XRESOLVE - undocumented

      In addition, it accepts '--limit-iface-in' and '--limit-iface-out' flags, specified as:

          src_type => ['LOCAL --limit-iface-in']

      It can also be negated using '!':

          src_type => ['! LOCAL']

      Will accept a single element or an array.
    PUPPETCODE

    newvalues(*[:UNSPEC, :UNICAST, :LOCAL, :BROADCAST, :ANYCAST, :MULTICAST,
                :BLACKHOLE, :UNREACHABLE, :PROHIBIT, :THROW, :NAT, :XRESOLVE].map { |address_type|
                [
                  address_type,
                  "! #{address_type}".to_sym,
                  "#{address_type} --limit-iface-in".to_sym,
                  "#{address_type} --limit-iface-out".to_sym,
                  "! #{address_type} --limit-iface-in".to_sym,
                  "! #{address_type} --limit-iface-out".to_sym,
                ]
              }.flatten)
  end

  # tcp-specific
  newproperty(:mss) do
    desc <<-PUPPETCODE
      Match a given TCP MSS value or range.
    PUPPETCODE
  end

  # tcp-specific
  newproperty(:tcp_flags, required_features: :tcp_flags) do
    desc <<-PUPPETCODE
      Match when the TCP flags are as specified.
      Is a string with a list of comma-separated flag names for the mask,
      then a space, then a comma-separated list of flags that should be set.
      The flags are: SYN ACK FIN RST URG PSH ALL NONE
      Note that you specify them in the order that iptables --list-rules
      would list them to avoid having puppet think you changed the flags.
      Example: FIN,SYN,RST,ACK SYN matches packets with the SYN bit set and the
      ACK,RST and FIN bits cleared. Such packets are used to request
      TCP  connection initiation.
    PUPPETCODE
  end

  # Iptables specific
  newproperty(:chain, required_features: :iptables) do
    desc <<-PUPPETCODE
      Name of the chain to use. Can be one of the built-ins:

      * INPUT
      * FORWARD
      * OUTPUT
      * PREROUTING
      * POSTROUTING

      Or you can provide a user-based chain.
    PUPPETCODE

    defaultto 'INPUT'
    newvalue(%r{^[a-zA-Z0-9\-_]+$})
  end

  newproperty(:table, required_features: :iptables) do
    desc <<-PUPPETCODE
      Table to use. Can be one of:

      * nat
      * mangle
      * filter
      * raw
      * rawpost
    PUPPETCODE

    newvalues(:nat, :mangle, :filter, :raw, :rawpost)
    defaultto 'filter'
  end

  newproperty(:jump, required_features: :iptables) do
    desc <<-PUPPETCODE
      The value for the iptables --jump parameter. Normal values are:

      * QUEUE
      * RETURN
      * DNAT
      * SNAT
      * LOG
      * NFLOG
      * MASQUERADE
      * REDIRECT
      * MARK
      * CT

      But any valid chain name is allowed.

      For the values ACCEPT, DROP, and REJECT, you must use the generic
      'action' parameter. This is to enfore the use of generic parameters where
      possible for maximum cross-platform modelling.

      If you set both 'accept' and 'jump' parameters, you will get an error as
      only one of the options should be set.
    PUPPETCODE

    validate do |value|
      unless %r{^[a-zA-Z0-9\-_]+$}.match?(value)
        raise ArgumentError, <<-PUPPETCODE
          Jump destination must consist of alphanumeric characters, an
          underscore or a hyphen.
        PUPPETCODE
      end

      if ['accept', 'reject', 'drop'].include?(value.downcase)
        raise ArgumentError, <<-PUPPETCODE
          Jump destination should not be one of ACCEPT, REJECT or DROP. Use
          the action property instead.
        PUPPETCODE
      end
    end
  end

  newproperty(:goto, required_features: :iptables) do
    desc <<-PUPPETCODE
      The value for the iptables --goto parameter. Normal values are:

      * QUEUE
      * RETURN
      * DNAT
      * SNAT
      * LOG
      * MASQUERADE
      * REDIRECT
      * MARK

      But any valid chain name is allowed.
    PUPPETCODE

    validate do |value|
      unless %r{^[a-zA-Z0-9\-_]+$}.match?(value)
        raise ArgumentError, <<-PUPPETCODE
          Goto destination must consist of alphanumeric characters, an
          underscore or a hyphen.
        PUPPETCODE
      end

      if ['accept', 'reject', 'drop'].include?(value.downcase)
        raise ArgumentError, <<-PUPPETCODE
          Goto destination should not be one of ACCEPT, REJECT or DROP. Use
          the action property instead.
        PUPPETCODE
      end
    end
  end

  # Interface specific matching properties
  newproperty(:iniface, required_features: :interface_match) do
    desc <<-PUPPETCODE
      Input interface to filter on.  Supports interface alias like eth0:0.
      To negate the match try this:

            iniface => '! lo',

    PUPPETCODE
    newvalues(%r{^!?\s?[a-zA-Z0-9\-\._\+\:@]+$})
  end

  newproperty(:outiface, required_features: :interface_match) do
    desc <<-PUPPETCODE
      Output interface to filter on.  Supports interface alias like eth0:0.
     To negate the match try this:

           outiface => '! lo',

    PUPPETCODE
    newvalues(%r{^!?\s?[a-zA-Z0-9\-\._\+\:@]+$})
  end

  # NAT specific properties
  newproperty(:tosource, required_features: :snat) do
    desc <<-PUPPETCODE
      When using jump => "SNAT" you can specify the new source address using
      this parameter.
    PUPPETCODE
  end

  newproperty(:todest, required_features: :dnat) do
    desc <<-PUPPETCODE
      When using jump => "DNAT" you can specify the new destination address
      using this paramter.
    PUPPETCODE
  end

  newproperty(:toports, required_features: :dnat) do
    desc <<-PUPPETCODE
      For DNAT this is the port that will replace the destination port.
    PUPPETCODE
  end

  newproperty(:to, required_features: :netmap) do
    desc <<-PUPPETCODE
      For NETMAP this will replace the destination IP
    PUPPETCODE
  end

  newproperty(:random_fully, required_features: :random_fully) do
    desc <<-PUPPETCODE
      When using a jump value of "MASQUERADE", "DNAT", "REDIRECT", or "SNAT"
      this boolean will enable fully randomized port mapping.

      **NOTE** Requires Kernel >= 3.13 and iptables >= 1.6.2
    PUPPETCODE

    newvalues(:true, :false)
  end

  newproperty(:random, required_features: :dnat) do
    desc <<-PUPPETCODE
      When using a jump value of "MASQUERADE", "DNAT", "REDIRECT", or "SNAT"
      this boolean will enable randomized port mapping.
    PUPPETCODE

    newvalues(:true, :false)
  end

  # Reject ICMP type
  newproperty(:reject, required_features: :reject_type) do
    desc <<-PUPPETCODE
      When combined with action => "REJECT" you can specify a different icmp
      response to be sent back to the packet sender.
    PUPPETCODE
  end

  # Logging properties
  newproperty(:log_level, required_features: :log_level) do
    desc <<-PUPPETCODE
      When combined with jump => "LOG" specifies the system log level to log
      to.
    PUPPETCODE

    munge do |value|
      if value.is_a?(String)
        value = @resource.log_level_name_to_number(value)
      else
        value
      end

      if value.nil? && value != ''
        raise('Unable to determine log level')
      end
      value
    end
  end

  newproperty(:log_prefix, required_features: :log_prefix) do
    desc <<-PUPPETCODE
      When combined with jump => "LOG" specifies the log prefix to use when
      logging.
    PUPPETCODE

    munge do |value|
      if value == ''
        raise('log_prefix should not be an empty string')
      end
      value
    end
  end

  newproperty(:log_uid, required_features: :log_uid) do
    desc <<-PUPPETCODE
      When combined with jump => "LOG" specifies the uid of the process making
      the connection.
    PUPPETCODE

    newvalues(:true, :false)
  end

  newproperty(:log_tcp_sequence, required_features: :log_tcp_sequence) do
    desc <<-PUPPETCODE
      When combined with jump => "LOG" enables logging of the TCP sequence
      numbers.
    PUPPETCODE

    newvalues(:true, :false)
  end

  newproperty(:log_tcp_options, required_features: :log_tcp_options) do
    desc <<-PUPPETCODE
      When combined with jump => "LOG" logging of the TCP packet
      header.
    PUPPETCODE

    newvalues(:true, :false)
  end

  newproperty(:log_ip_options, required_features: :log_ip_options) do
    desc <<-PUPPETCODE
      When combined with jump => "LOG" logging of the TCP IP/IPv6
      packet header.
    PUPPETCODE

    newvalues(:true, :false)
  end

  newproperty(:nflog_group, required_features: :nflog_group) do
    desc <<-PUPPETCODE
      Used with the jump target NFLOG.
      The netlink group (0 - 2^16-1) to which packets are (only applicable
      for nfnetlink_log). Defaults to 0.
    PUPPETCODE

    validate do |value|
      if value.to_i > (2**16) - 1 || value.to_i < 0
        raise ArgumentError, 'nflog_group must be between 0 and 2^16-1'
      end
    end

    munge do |value|
      if value.is_a?(String) && value =~ %r{^[-0-9]+$}
        Integer(value)
      else
        value
      end
    end
  end

  newproperty(:nflog_prefix, required_features: :nflog_prefix) do
    desc <<-PUPPETCODE
      Used with the jump target NFLOG.
      A prefix string to include in the log message, up to 64 characters long,
      useful for distinguishing messages in the logs.
    PUPPETCODE

    validate do |value|
      if value.length > 64
        raise ArgumentError, 'nflog_prefix must be less than 64 characters.'
      end
    end
  end

  newproperty(:nflog_range, required_features: :nflog_range) do
    desc <<-PUPPETCODE
      Used with the jump target NFLOG.
      This has never worked, use nflog_size instead.
    PUPPETCODE
  end

  newproperty(:nflog_size, required_features: :nflog_size) do
    desc <<-PUPPETCODE
      Used with the jump target NFLOG.
      The number of bytes to be copied to userspace (only applicable for nfnetlink_log).
      nfnetlink_log instances may specify their own size, this option overrides it.
    PUPPETCODE
  end

  newproperty(:nflog_threshold, required_features: :nflog_threshold) do
    desc <<-PUPPETCODE
      Used with the jump target NFLOG.
      Number of packets to queue inside the kernel before sending them to userspace
      (only applicable for nfnetlink_log). Higher values result in less overhead
      per packet, but increase delay until the packets reach userspace. Defaults to 1.
    PUPPETCODE

    munge do |value|
      if value.is_a?(String) && value =~ %r{^[-0-9]+$}
        Integer(value)
      else
        value
      end
    end
  end

  # ICMP matching property
  newproperty(:icmp, required_features: :icmp_match) do
    desc <<-PUPPETCODE
      When matching ICMP packets, this is the type of ICMP packet to match.

      A value of "any" is not supported. To achieve this behaviour the
      parameter should simply be omitted or undefined.
      An array of values is also not supported. To match against multiple ICMP
      types, please use separate rules for each ICMP type.
    PUPPETCODE

    validate do |value|
      if value == 'any'
        raise ArgumentError,
              "Value 'any' is not valid. This behaviour should be achieved " \
              'by omitting or undefining the ICMP parameter.'
      end
      if value.is_a?(Array)
        raise ArgumentError,
              'Argument must not be an array of values. To match multiple ' \
              'ICMP types, please use separate rules for each ICMP type.'
      end
    end

    munge do |value|
      if value.is_a?(String)
        # ICMP codes differ between IPv4 and IPv6.
        case @resource[:provider]
        when :iptables
          protocol = 'inet'
        when :ip6tables
          protocol = 'inet6'
        else
          raise('cannot work out protocol family')
        end

        value = @resource.icmp_name_to_number(value, protocol)
      else
        value
      end

      if value.nil? && value != ''
        raise('cannot work out icmp type')
      end
      value
    end
  end

  newproperty(:state, array_matching: :all, required_features: :state_match) do
    desc <<-PUPPETCODE
      Matches a packet based on its state in the firewall stateful inspection
      table. Values can be:

      * INVALID
      * ESTABLISHED
      * NEW
      * RELATED
      * UNTRACKED
    PUPPETCODE

    newvalues(:INVALID, :ESTABLISHED, :NEW, :RELATED, :UNTRACKED)

    # States should always be sorted. This normalizes the resource states to
    # keep it consistent with the sorted result from iptables-save.
    def should=(values)
      @should = super(values).sort_by { |sym| sym.to_s }
    end

    def to_s?(value)
      should_to_s(value)
    end

    def should_to_s(value)
      value = [value] unless value.is_a?(Array)
      value.join(',')
    end
  end

  newproperty(:ctstate, array_matching: :all, required_features: :conntrack) do
    desc <<-PUPPETCODE
      Matches a packet based on its state in the firewall stateful inspection
      table, using the conntrack module. Values can be:

      * INVALID
      * ESTABLISHED
      * NEW
      * RELATED
      * UNTRACKED
      * SNAT
      * DNAT
    PUPPETCODE

    newvalues(:INVALID, :ESTABLISHED, :NEW, :RELATED, :UNTRACKED, :SNAT, :DNAT)

    # States should always be sorted. This normalizes the resource states to
    # keep it consistent with the sorted result from iptables-save.
    def should=(values)
      @should = super(values).sort_by { |sym| sym.to_s }
    end

    def to_s?(value)
      should_to_s(value)
    end

    def should_to_s(value)
      value = [value] unless value.is_a?(Array)
      value.join(',')
    end
  end

  newproperty(:ctproto, required_features: :conntrack) do
    desc <<-PUPPETCODE
      The specific layer-4 protocol number to match for this rule using the
      conntrack module.
    PUPPETCODE
    newvalue(%r{^!?\s?\d+$})
  end

  newproperty(:ctorigsrc, required_features: :conntrack) do
    desc <<-PUPPETCODE
      The original source address using the conntrack module. For example:

          ctorigsrc => '192.168.2.0/24'

      You can also negate a mask by putting ! in front. For example:

          ctorigsrc => '! 192.168.2.0/24'

      The ctorigsrc can also be an IPv6 address if your provider supports it.
    PUPPETCODE

    munge do |value|
      case @resource[:provider]
      when :iptables
        protocol = :IPv4
      when :ip6tables
        protocol = :IPv6
      else
        raise('cannot work out protocol family')
      end

      begin
        @resource.host_to_mask(value, protocol)
        if protocol == :IPv4
          value.chomp('/32')
        elsif protocol == :IPv6
          value.chomp('/128')
        end
      rescue StandardError => e
        raise("host_to_ip failed for #{value}, exception #{e}")
      end
    end
  end

  newproperty(:ctorigdst, required_features: :conntrack) do
    desc <<-PUPPETCODE
      The original destination address using the conntrack module. For example:

          ctorigdst => '192.168.2.0/24'

      You can also negate a mask by putting ! in front. For example:

          ctorigdst => '! 192.168.2.0/24'

      The ctorigdst can also be an IPv6 address if your provider supports it.
    PUPPETCODE

    munge do |value|
      case @resource[:provider]
      when :iptables
        protocol = :IPv4
      when :ip6tables
        protocol = :IPv6
      else
        raise('cannot work out protocol family')
      end

      begin
        @resource.host_to_mask(value, protocol)
        if protocol == :IPv4
          value.chomp('/32')
        elsif protocol == :IPv6
          value.chomp('/128')
        end
      rescue StandardError => e
        raise("host_to_ip failed for #{value}, exception #{e}")
      end
    end
  end

  newproperty(:ctreplsrc, required_features: :conntrack) do
    desc <<-PUPPETCODE
      The reply source address using the conntrack module. For example:

          ctreplsrc => '192.168.2.0/24'

      You can also negate a mask by putting ! in front. For example:

          ctreplsrc => '! 192.168.2.0/24'

      The ctreplsrc can also be an IPv6 address if your provider supports it.
    PUPPETCODE

    munge do |value|
      case @resource[:provider]
      when :iptables
        protocol = :IPv4
      when :ip6tables
        protocol = :IPv6
      else
        raise('cannot work out protocol family')
      end

      begin
        @resource.host_to_mask(value, protocol)
        if protocol == :IPv4
          value.chomp('/32')
        elsif protocol == :IPv6
          value.chomp('/128')
        end
      rescue StandardError => e
        raise("host_to_ip failed for #{value}, exception #{e}")
      end
    end
  end

  newproperty(:ctrepldst, required_features: :conntrack) do
    desc <<-PUPPETCODE
      The reply destination address using the conntrack module. For example:

          ctrepldst => '192.168.2.0/24'

      You can also negate a mask by putting ! in front. For example:

          ctrepldst => '! 192.168.2.0/24'

      The ctrepldst can also be an IPv6 address if your provider supports it.
    PUPPETCODE

    munge do |value|
      case @resource[:provider]
      when :iptables
        protocol = :IPv4
      when :ip6tables
        protocol = :IPv6
      else
        raise('cannot work out protocol family')
      end

      begin
        @resource.host_to_mask(value, protocol)
        if protocol == :IPv4
          value.chomp('/32')
        elsif protocol == :IPv6
          value.chomp('/128')
        end
      rescue StandardError => e
        raise("host_to_ip failed for #{value}, exception #{e}")
      end
    end
  end

  newproperty(:ctorigsrcport, required_features: :conntrack) do
    desc <<-PUPPETCODE
      The original source port to match for this filter using the conntrack module.
      For example:

          ctorigsrcport => '80'

      You can also specify a port range: For example:

          ctorigsrcport => '80:81'

      You can also negate a port by putting ! in front. For example:

          ctorigsrcport => '! 80'

    PUPPETCODE
    newvalue(%r{^!?\s?\d+$|^!?\s?\d+\:\d+$})
  end

  newproperty(:ctorigdstport, required_features: :conntrack) do
    desc <<-PUPPETCODE
      The original destination port to match for this filter using the conntrack module.
      For example:

          ctorigdstport => '80'

      You can also specify a port range: For example:

          ctorigdstport => '80:81'

      You can also negate a port by putting ! in front. For example:

          ctorigdstport => '! 80'

    PUPPETCODE
    newvalue(%r{^!?\s?\d+$|^!?\s?\d+\:\d+$})
  end

  newproperty(:ctreplsrcport, required_features: :conntrack) do
    desc <<-PUPPETCODE
      The reply source port to match for this filter using the conntrack module.
      For example:

          ctreplsrcport => '80'

      You can also specify a port range: For example:

          ctreplsrcport => '80:81'

      You can also negate a port by putting ! in front. For example:

          ctreplsrcport => '! 80'

    PUPPETCODE
    newvalue(%r{^!?\s?\d+$|^!?\s?\d+\:\d+$})
  end

  newproperty(:ctrepldstport, required_features: :conntrack) do
    desc <<-PUPPETCODE
      The reply destination port to match for this filter using the conntrack module.
      For example:

          ctrepldstport => '80'

      You can also specify a port range: For example:

          ctrepldstport => '80:81'

      You can also negate a port by putting ! in front. For example:

          ctrepldstport => '! 80'

    PUPPETCODE
    newvalue(%r{^!?\s?\d+$|^!?\s?\d+\:\d+$})
  end

  newproperty(:ctstatus, array_matching: :all, required_features: :conntrack) do
    desc <<-PUPPETCODE
      Matches a packet based on its status using the conntrack module. Values can be:

      * EXPECTED
      * SEEN_REPLY
      * ASSURED
      * CONFIRMED
    PUPPETCODE

    newvalues(:NONE, :EXPECTED, :SEEN_REPLY, :ASSURED, :CONFIRMED)

    # Statuses should always be sorted. This normalizes the resource status to
    # keep it consistent with the sorted result from iptables-save.
    def should=(values)
      @should = super(values).sort_by { |sym| sym.to_s }
    end

    def to_s?(value)
      should_to_s(value)
    end

    def should_to_s(value)
      value = [value] unless value.is_a?(Array)
      value.join(',')
    end
  end

  newproperty(:ctexpire, required_features: :conntrack) do
    desc <<-PUPPETCODE
      Matches a packet based on lifetime remaining in seconds or range of values
      using the conntrack module. For example:

          ctexpire => '100:150'

    PUPPETCODE
    newvalue(%r{^!?\s?\d+$|^!?\s?\d+\:\d+$})
  end

  newproperty(:ctdir, required_features: :conntrack) do
    desc <<-PUPPETCODE
      Matches a packet that is flowing in the specified direction using the
      conntrack module. If this flag is not specified at all, matches packets
      in both directions. Values can be:

      * REPLY
      * ORIGINAL
    PUPPETCODE

    newvalues(:REPLY, :ORIGINAL)
  end

  # Connection mark
  newproperty(:connmark, required_features: :mark) do
    desc <<-PUPPETCODE
      Match the Netfilter mark value associated with the packet.  Accepts either of:
      mark/mask or mark.  These will be converted to hex if they are not already.
    PUPPETCODE
    munge do |value|
      int_or_hex = '[a-fA-F0-9x]'
      match = value.to_s.match("(#{int_or_hex}+)(/)?(#{int_or_hex}+)?")
      mark = @resource.to_hex32(match[1])

      # Values that can't be converted to hex.
      # Or contain a trailing slash with no mask.
      if mark.nil? || (mark && match[2] && match[3].nil?)
        raise ArgumentError, 'MARK value must be integer or hex between 0 and 0xffffffff'
      end

      # There should not be a mask on connmark
      unless match[3].nil?
        raise ArgumentError, 'iptables does not support masks on MARK match rules'
      end
      value = mark

      value
    end
  end

  # Connection limiting properties
  newproperty(:connlimit_above, required_features: :connection_limiting) do
    desc <<-PUPPETCODE
      Connection limiting value for matched connections above n.
    PUPPETCODE
    newvalue(%r{^\d+$})
  end

  newproperty(:connlimit_mask, required_features: :connection_limiting) do
    desc <<-PUPPETCODE
      Connection limiting by subnet mask for matched connections.
      IPv4: 0-32
      IPv6: 0-128
    PUPPETCODE
    newvalue(%r{^\d+$})
  end

  # Hop limiting properties
  newproperty(:hop_limit, required_features: :hop_limiting) do
    desc <<-PUPPETCODE
      Hop limiting value for matched packets.
    PUPPETCODE
    newvalue(%r{^\d+$})
  end

  # Rate limiting properties
  newproperty(:limit, required_features: :rate_limiting) do
    desc <<-PUPPETCODE
      Rate limiting value for matched packets. The format is:
      rate/[/second/|/minute|/hour|/day].

      Example values are: '50/sec', '40/min', '30/hour', '10/day'."
    PUPPETCODE
  end

  newproperty(:burst, required_features: :rate_limiting) do
    desc <<-PUPPETCODE
      Rate limiting burst value (per second) before limit checks apply.
    PUPPETCODE
    newvalue(%r{^\d+$})
  end

  newproperty(:uid, required_features: :owner) do
    desc <<-PUPPETCODE
      UID or Username owner matching rule.  Accepts a string argument
      only, as iptables does not accept multiple uid in a single
      statement.
    PUPPETCODE
    def insync?(is)
      return false unless is

      require 'etc'

      # The following code allow us to take into consideration unix mappings
      # between string usernames and UIDs (integers). We also need to ignore
      # spaces as they are irrelevant with respect to rule sync.

      # Remove whitespace
      is = is.gsub(%r{\s+}, '')
      should = @should.first.to_s.gsub(%r{\s+}, '')

      # Keep track of negation, but remove the '!'
      is_negate = ''
      should_negate = ''
      if is.start_with?('!')
        is = is.gsub(%r{^!}, '')
        is_negate = '!'
      end
      if should.start_with?('!')
        should = should.gsub(%r{^!}, '')
        should_negate = '!'
      end

      # If 'should' contains anything other than digits or digit range,
      # we assume that we have to do a lookup to convert
      # to UID
      unless should[%r{[0-9]+(-[0-9]+)?}] == should
        should = Etc.getpwnam(should).uid
      end

      # If 'is' contains anything other than digits or digit range,
      # we assume that we have to do a lookup to convert
      # to UID
      unless is[%r{[0-9]+(-[0-9]+)?}] == is
        is = Etc.getpwnam(is).uid
      end

      "#{is_negate}#{is}" == "#{should_negate}#{should}"
    end
  end

  newproperty(:gid, required_features: :owner) do
    desc <<-PUPPETCODE
      GID or Group owner matching rule.  Accepts a string argument
      only, as iptables does not accept multiple gid in a single
      statement.
    PUPPETCODE
    def insync?(is)
      return false unless is

      require 'etc'

      # The following code allow us to take into consideration unix mappings
      # between string group names and GIDs (integers). We also need to ignore
      # spaces as they are irrelevant with respect to rule sync.

      # Remove whitespace
      is = is.gsub(%r{\s+}, '')
      should = @should.first.to_s.gsub(%r{\s+}, '')

      # Keep track of negation, but remove the '!'
      is_negate = ''
      should_negate = ''
      if is.start_with?('!')
        is = is.gsub(%r{^!}, '')
        is_negate = '!'
      end
      if should.start_with?('!')
        should = should.gsub(%r{^!}, '')
        should_negate = '!'
      end

      # If 'should' contains anything other than digits or digit range,
      # we assume that we have to do a lookup to convert
      # to GID
      unless should[%r{[0-9]+(-[0-9]+)?}] == should
        should = Etc.getgrnam(should).gid
      end

      # If 'is' contains anything other than digits or digit range,
      # we assume that we have to do a lookup to convert
      # to GID
      unless is[%r{[0-9]+(-[0-9]+)?}] == is
        is = Etc.getgrnam(is).gid
      end

      "#{is_negate}#{is}" == "#{should_negate}#{should}"
    end
  end

  # match mark
  newproperty(:match_mark, required_features: :mark) do
    desc <<-PUPPETCODE
      Match the Netfilter mark value associated with the packet.  Accepts either of:
      mark/mask or mark.  These will be converted to hex if they are not already.
    PUPPETCODE
    munge do |value|
      mark_regex = %r{\A((?:0x)?[0-9A-F]+)(/)?((?:0x)?[0-9A-F]+)?\z}i
      match = value.to_s.match(mark_regex)
      if match.nil?
        raise ArgumentError, 'Match MARK value must be integer or hex between 0 and 0xffffffff'
      end
      mark = @resource.to_hex32(match[1])

      # Values that can't be converted to hex.
      # Or contain a trailing slash with no mask.
      if mark.nil? || (mark && match[2] && match[3].nil?)
        raise ArgumentError, 'Match MARK value must be integer or hex between 0 and 0xffffffff'
      end

      # There should not be a mask on match_mark
      unless match[3].nil?
        raise ArgumentError, 'iptables does not support masks on MARK match rules'
      end
      value = mark

      value
    end
  end

  newproperty(:set_mark, required_features: :mark) do
    desc <<-PUPPETCODE
      Set the Netfilter mark value associated with the packet.  Accepts either of:
      mark/mask or mark.  These will be converted to hex if they are not already.
    PUPPETCODE

    munge do |value|
      int_or_hex = '[a-fA-F0-9x]'
      match = value.to_s.match("(#{int_or_hex}+)(/)?(#{int_or_hex}+)?")
      mark = @resource.to_hex32(match[1])

      # Values that can't be converted to hex.
      # Or contain a trailing slash with no mask.
      if mark.nil? || (mark && match[2] && match[3].nil?)
        raise ArgumentError, 'MARK value must be integer or hex between 0 and 0xffffffff'
      end

      # Old iptables does not support a mask. New iptables will expect one.
      iptables_version = Facter.value('iptables_version')
      mask_required = (iptables_version && Puppet::Util::Package.versioncmp(iptables_version, '1.4.1') >= 0)

      if mask_required
        if match[3].nil?
          value = "#{mark}/0xffffffff"
        else
          mask = @resource.to_hex32(match[3])
          if mask.nil?
            raise ArgumentError, 'MARK mask must be integer or hex between 0 and 0xffffffff'
          end
          value = "#{mark}/#{mask}"
        end
      else
        unless match[3].nil?
          raise ArgumentError, "iptables version #{iptables_version} does not support masks on MARK rules"
        end
        value = mark
      end

      value
    end
  end

  newproperty(:clamp_mss_to_pmtu, required_features: :iptables) do
    desc <<-PUPPETCODE
      Sets the clamp mss to pmtu flag.
    PUPPETCODE

    newvalues(:true, :false)
  end

  newproperty(:set_dscp, required_features: :iptables) do
    desc <<-PUPPETCODE
      Set DSCP Markings.
    PUPPETCODE
  end

  newproperty(:set_dscp_class, required_features: :iptables) do
    desc <<-PUPPETCODE
      This sets the DSCP field according to a predefined DiffServ class.
    PUPPETCODE
    #  iptables uses the cisco DSCP classes as the basis for this flag. Values may be found here:
    #  'http://www.cisco.com/c/en/us/support/docs/quality-of-service-qos/qos-packet-marking/10103-dscpvalues.html'
    valid_codes = ['af11', 'af12', 'af13', 'af21', 'af22', 'af23', 'af31', 'af32', 'af33', 'af41', 'af42', 'af43', 'cs1', 'cs2', 'cs3', 'cs4', 'cs5', 'cs6', 'cs7', 'ef']
    munge do |value|
      unless valid_codes.include? value.downcase
        raise ArgumentError, "#{value} is not a valid DSCP Class"
      end
      value.downcase
    end
  end

  newproperty(:set_mss, required_features: :iptables) do
    desc <<-PUPPETCODE
      Sets the TCP MSS value for packets.
    PUPPETCODE
  end

  newproperty(:pkttype, required_features: :pkttype) do
    desc <<-PUPPETCODE
      Sets the packet type to match.
    PUPPETCODE

    newvalues(:unicast, :broadcast, :multicast)
  end

  newproperty(:isfragment, required_features: :isfragment) do
    desc <<-PUPPETCODE
      Set to true to match tcp fragments (requires type to be set to tcp)
    PUPPETCODE

    newvalues(:true, :false)
  end

  newproperty(:recent, required_features: :recent_limiting) do
    desc <<-PUPPETCODE
      Enable the recent module. Takes as an argument one of set, update,
      rcheck or remove. For example:

        ```
        # If anyone's appeared on the 'badguy' blacklist within
        #  the last 60 seconds, drop their traffic, and update the timestamp.
        firewall { '100 Drop badguy traffic':
          recent   => 'update',
          rseconds => 60,
          rsource  => true,
          rname    => 'badguy',
          action   => 'DROP',
          chain    => 'FORWARD',
        }
        ```


        ```
        # No-one should be sending us traffic on eth0 from the
        #  localhost, Blacklist them
        firewall { '101 blacklist strange traffic':
          recent      => 'set',
          rsource     => true,
          rname       => 'badguy',
          destination => '127.0.0.0/8',
          iniface     => 'eth0',
          action      => 'DROP',
          chain       => 'FORWARD',
        }
        ```
    PUPPETCODE

    newvalues(:set, :update, :rcheck, :remove)
    munge do |value|
      _value = '--' + value
    end
  end

  newproperty(:rdest, required_features: :recent_limiting) do
    desc <<-PUPPETCODE
      Recent module; add the destination IP address to the list.
      Must be boolean true.
    PUPPETCODE

    newvalues(:true, :false)
  end

  newproperty(:rsource, required_features: :recent_limiting) do
    desc <<-PUPPETCODE
      Recent module; add the source IP address to the list.
      Must be boolean true.
    PUPPETCODE

    newvalues(:true, :false)
  end

  newproperty(:rname, required_features: :recent_limiting) do
    desc <<-PUPPETCODE
      Recent module; The name of the list. Takes a string argument.
    PUPPETCODE
  end

  newproperty(:rseconds, required_features: :recent_limiting) do
    desc <<-PUPPETCODE
      Recent module; used in conjunction with one of `recent => 'rcheck'` or
      `recent => 'update'`. When used, this will narrow the match to only
      happen when the address is in the list and was seen within the last given
      number of seconds.
    PUPPETCODE
  end

  newproperty(:reap, required_features: :recent_limiting) do
    desc <<-PUPPETCODE
      Recent module; can only be used in conjunction with the `rseconds`
      attribute. When used, this will cause entries older than 'seconds' to be
      purged.  Must be boolean true.
    PUPPETCODE

    newvalues(:true, :false)
  end

  newproperty(:rhitcount, required_features: :recent_limiting) do
    desc <<-PUPPETCODE
      Recent module; used in conjunction with `recent => 'update'` or `recent
      => 'rcheck'. When used, this will narrow the match to only happen when
      the address is in the list and packets had been received greater than or
      equal to the given value.
    PUPPETCODE
  end

  newproperty(:rttl, required_features: :recent_limiting) do
    desc <<-PUPPETCODE
      Recent module; may only be used in conjunction with one of `recent =>
      'rcheck'` or `recent => 'update'`. When used, this will narrow the match
      to only happen when the address is in the list and the TTL of the current
      packet matches that of the packet which hit the `recent => 'set'` rule.
      This may be useful if you have problems with people faking their source
      address in order to DoS you via this module by disallowing others access
      to your site by sending bogus packets to you.  Must be boolean true.
    PUPPETCODE

    newvalues(:true, :false)
  end

  newproperty(:rpfilter, required_features: :rpfilter, array_matching: :all) do
    desc <<-PUPPETCODE
      Enable the rpfilter module.
    PUPPETCODE

    newvalues(:loose, :validmark, :'accept-local', :invert)
    munge do |value|
      _value = '--' + value
    end

    def insync?(is)
      is.to_set == should.to_set
    end
  end

  newproperty(:socket, required_features: :socket) do
    desc <<-PUPPETCODE
      If true, matches if an open socket can be found by doing a coket lookup
      on the packet.
    PUPPETCODE

    newvalues(:true, :false)
  end

  newproperty(:ishasmorefrags, required_features: :ishasmorefrags) do
    desc <<-PUPPETCODE
      If true, matches if the packet has it's 'more fragments' bit set. ipv6.
    PUPPETCODE

    newvalues(:true, :false)
  end

  newproperty(:islastfrag, required_features: :islastfrag) do
    desc <<-PUPPETCODE
      If true, matches if the packet is the last fragment. ipv6.
    PUPPETCODE

    newvalues(:true, :false)
  end

  newproperty(:isfirstfrag, required_features: :isfirstfrag) do
    desc <<-PUPPETCODE
      If true, matches if the packet is the first fragment.
      Sadly cannot be negated. ipv6.
    PUPPETCODE

    newvalues(:true, :false)
  end

  newproperty(:ipsec_policy, required_features: :ipsec_policy) do
    desc <<-PUPPETCODE
       Sets the ipsec policy type. May take a combination of arguments for any flags that can be passed to `--pol ipsec` such as: `--strict`, `--reqid 100`, `--next`, `--proto esp`, etc.
    PUPPETCODE

    newvalues(:none, :ipsec)
  end

  newproperty(:ipsec_dir, required_features: :ipsec_dir) do
    desc <<-PUPPETCODE
       Sets the ipsec policy direction
    PUPPETCODE

    newvalues(:in, :out)
  end

  newproperty(:stat_mode) do
    desc <<-PUPPETCODE
      Set the matching mode for statistic matching.
    PUPPETCODE

    newvalues(:nth, :random)
  end

  newproperty(:stat_every) do
    desc <<-PUPPETCODE
      Match one packet every nth packet. Requires `stat_mode => 'nth'`
    PUPPETCODE

    validate do |value|
      unless %r{^\d+$}.match?(value)
        raise ArgumentError, <<-PUPPETCODE
          stat_every value must be a digit
        PUPPETCODE
      end

      unless value.to_i > 0
        raise ArgumentError, <<-PUPPETCODE
          stat_every value must be larger than 0
        PUPPETCODE
      end
    end
  end

  newproperty(:stat_packet) do
    desc <<-PUPPETCODE
      Set the initial counter value for the nth mode. Must be between 0 and the value of `stat_every`. Defaults to 0. Requires `stat_mode => 'nth'`
    PUPPETCODE

    newvalues(%r{^\d+$})
  end

  newproperty(:stat_probability) do
    desc <<-PUPPETCODE
      Set the probability from 0 to 1 for a packet to be randomly matched. It works only with `stat_mode => 'random'`.
    PUPPETCODE

    validate do |value|
      unless value =~ %r{^([01])\.(\d+)$}
        raise ArgumentError, <<-PUPPETCODE
          stat_probability must be between 0.0 and 1.0
        PUPPETCODE
      end

      if Regexp.last_match(1).to_i == 1 && Regexp.last_match(2).to_i != 0
        raise ArgumentError, <<-PUPPETCODE
          start_probability must be between 0.0 and 1.0
        PUPPETCODE
      end
    end
  end

  newproperty(:mask, required_features: :mask) do
    desc <<-PUPPETCODE
      Sets the mask to use when `recent` is enabled.
    PUPPETCODE
  end

  newproperty(:gateway, required_features: :iptables) do
    desc <<-PUPPETCODE
      The TEE target will clone a packet and redirect this clone to another
      machine on the local network segment. gateway is the target host's IP.
    PUPPETCODE
  end

  newproperty(:ipset, required_features: :ipset, array_matching: :all) do
    desc <<-PUPPETCODE
      Matches against the specified ipset list.
      Requires ipset kernel module. Will accept a single element or an array.
      The value is the name of the blacklist, followed by a space, and then
      'src' and/or 'dst' separated by a comma.
      For example: 'blacklist src,dst'
    PUPPETCODE

    def to_s?(value)
      should_to_s(value)
    end

    def should_to_s(value)
      value = [value] unless value.is_a?(Array)
      value.join(', ')
    end
  end

  newproperty(:checksum_fill, required_features: :iptables) do
    desc <<-PUPPETCODE
      Compute and fill missing packet checksums.
    PUPPETCODE

    newvalues(:true, :false)
  end

  newparam(:line) do
    desc <<-PUPPETCODE
      Read-only property for caching the rule line.
    PUPPETCODE
  end

  newproperty(:mac_source) do
    desc <<-PUPPETCODE
      MAC Source
    PUPPETCODE
    newvalues(%r{^([0-9a-f]{2}[:]){5}([0-9a-f]{2})$}i)
    facter_os_name = Facter.value(:os)['name'].downcase
    facter_os_release = Facter.value(:os)['release']['major']
    if ['ubuntu-22.04', 'debian-11', 'sles-15'].include?("#{facter_os_name}-#{facter_os_release}")
      munge do |value|
        _value = value.downcase
      end
    end
  end

  newproperty(:physdev_in, required_features: :iptables) do
    desc <<-PUPPETCODE
      Match if the packet is entering a bridge from the given interface.
    PUPPETCODE
    newvalues(%r{^[a-zA-Z0-9\-\._\+]+$})
  end

  newproperty(:physdev_out, required_features: :iptables) do
    desc <<-PUPPETCODE
      Match if the packet is leaving a bridge via the given interface.
    PUPPETCODE
    newvalues(%r{^[a-zA-Z0-9\-\._\+]+$})
  end

  newproperty(:physdev_is_bridged, required_features: :iptables) do
    desc <<-PUPPETCODE
      Match if the packet is transversing a bridge.
    PUPPETCODE
    newvalues(:true, :false)
  end

  newproperty(:physdev_is_in, required_features: :iptables) do
    desc <<-PUPPETCODE
      Matches if the packet has entered through a bridge interface.
    PUPPETCODE
    newvalues(:true, :false)
  end

  newproperty(:physdev_is_out, required_features: :iptables) do
    desc <<-PUPPETCODE
      Matches if the packet will leave through a bridge interface.
    PUPPETCODE
    newvalues(:true, :false)
  end

  newproperty(:date_start, required_features: :iptables) do
    desc <<-PUPPETCODE
      Only match during the given time, which must be in ISO 8601 "T" notation.
      The possible time range is 1970-01-01T00:00:00 to 2038-01-19T04:17:07
    PUPPETCODE
  end

  newproperty(:date_stop, required_features: :iptables) do
    desc <<-PUPPETCODE
      Only match during the given time, which must be in ISO 8601 "T" notation.
      The possible time range is 1970-01-01T00:00:00 to 2038-01-19T04:17:07
    PUPPETCODE
  end

  newproperty(:time_start, required_features: :iptables) do
    desc <<-PUPPETCODE
      Only match during the given daytime. The possible time range is 00:00:00 to 23:59:59.
      Leading zeroes are allowed (e.g. "06:03") and correctly interpreted as base-10.
    PUPPETCODE

    munge do |value|
      if %r{^([0-9]):}.match?(value)
        value = "0#{value}"
      end

      if %r{^([0-9]|0[0-9]|1[0-9]|2[0-3]):[0-5][0-9]$}.match?(value)
        value = "#{value}:00"
      end

      value
    end
  end

  newproperty(:time_stop, required_features: :iptables) do
    desc <<-PUPPETCODE
      Only match during the given daytime. The possible time range is 00:00:00 to 23:59:59.
      Leading zeroes are allowed (e.g. "06:03") and correctly interpreted as base-10.
    PUPPETCODE

    munge do |value|
      if %r{^([0-9]):}.match?(value)
        value = "0#{value}"
      end

      if %r{^([0-9]|0[0-9]|1[0-9]|2[0-3]):[0-5][0-9]$}.match?(value)
        value = "#{value}:00"
      end

      value
    end
  end

  newproperty(:month_days, required_features: :iptables) do
    desc <<-PUPPETCODE
      Only match on the given days of the month. Possible values are 1 to 31.
      Note that specifying 31 will of course not match on months which do not have a 31st day;
      the same goes for 28- or 29-day February.
    PUPPETCODE

    validate do |value|
      month = value.to_i
      if month >= 1 && month <= 31
        value
      else
        raise ArgumentError,
              'month_days must be in the range of 1-31'
      end
    end
  end

  newproperty(:week_days, required_features: :iptables) do
    desc <<-PUPPETCODE
      Only match on the given weekdays.
    PUPPETCODE

    newvalues(:Mon, :Tue, :Wed, :Thu, :Fri, :Sat, :Sun)
  end

  newproperty(:time_contiguous, required_features: :iptables) do
    desc <<-PUPPETCODE
      When time_stop is smaller than time_start value, match this as a single time period instead distinct intervals.
    PUPPETCODE

    newvalues(:true, :false)
  end

  newproperty(:kernel_timezone, required_features: :iptables) do
    desc <<-PUPPETCODE
      Use the kernel timezone instead of UTC to determine whether a packet meets the time regulations.
    PUPPETCODE

    newvalues(:true, :false)
  end

  newproperty(:clusterip_new, required_features: :clusterip) do
    desc <<-PUPPETCODE
      Used with the CLUSTERIP jump target.
      Create a new ClusterIP. You always have to set this on the first rule for a given ClusterIP.
    PUPPETCODE

    newvalues(:true, :false)
  end

  newproperty(:clusterip_hashmode, required_features: :clusterip) do
    desc <<-PUPPETCODE
      Used with the CLUSTERIP jump target.
      Specify the hashing mode.
    PUPPETCODE

    newvalues(:sourceip, :'sourceip-sourceport', :'sourceip-sourceport-destport')
  end

  newproperty(:clusterip_clustermac, required_features: :clusterip) do
    desc <<-PUPPETCODE
      Used with the CLUSTERIP jump target.
      Specify the ClusterIP MAC address. Has to be a link-layer multicast address.
    PUPPETCODE

    newvalues(%r{^([0-9a-f]{2}[:]){5}([0-9a-f]{2})$}i)
  end

  newproperty(:clusterip_total_nodes, required_features: :clusterip) do
    desc <<-PUPPETCODE
      Used with the CLUSTERIP jump target.
      Number of total nodes within this cluster.
    PUPPETCODE

    newvalues(%r{\d+})
  end

  newproperty(:clusterip_local_node, required_features: :clusterip) do
    desc <<-PUPPETCODE
      Used with the CLUSTERIP jump target.
      Specify the random seed used for hash initialization.
    PUPPETCODE

    newvalues(%r{\d+})
  end

  newproperty(:clusterip_hash_init, required_features: :clusterip) do
    desc <<-PUPPETCODE
      Used with the CLUSTERIP jump target.
      Specify the random seed used for hash initialization.
    PUPPETCODE
  end

  newproperty(:length, required_features: :length) do
    desc <<-PUPPETCODE
      Sets the length of layer-3 payload to match.
    PUPPETCODE

    munge do |value|
      match = value.to_s.match('^([0-9]+)(-)?([0-9]+)?$')
      if match.nil?
        raise ArgumentError, 'Length value must either be an integer or a range'
      end

      low = match[1].to_i
      unless match[3].nil?
        high = match[3].to_i
      end

      if (low < 0 || low > 65_535) || \
         (!high.nil? && (high < 0 || high > 65_535 || high < low))
        raise ArgumentError, 'Length values must be between 0 and 65535'
      end

      value = low.to_s
      unless high.nil?
        value << ':' << high.to_s
      end
      value
    end
  end

  newproperty(:string, required_features: :string_matching) do
    desc <<-PUPPETCODE
      String matching feature. Matches the packet against the pattern
      given as an argument.
    PUPPETCODE
  end

  newproperty(:string_hex) do
    desc <<-PUPPETCODE
      String matching feature. Matches the package against the hex pattern
      given as an argument.
    PUPPETCODE
    munge do |value|
      _value = if value.include?('!')
                 value.split('|').map { |x| x.include?('!') ? x : "|#{x.delete(' ')}|" }.join
               else
                 value.delete(' ')
               end
    end
  end

  newproperty(:string_algo, required_features: :string_matching) do
    desc <<-PUPPETCODE
      String matching feature, pattern matching strategy.
    PUPPETCODE

    newvalues(:bm, :kmp)
  end

  newproperty(:string_from, required_features: :string_matching) do
    desc <<-PUPPETCODE
      String matching feature, offset from which we start looking for any matching.
    PUPPETCODE
  end

  newproperty(:string_to, required_features: :string_matching) do
    desc <<-PUPPETCODE
      String matching feature, offset up to which we should scan.
    PUPPETCODE
  end

  newproperty(:queue_num, required_features: :queue_num) do
    desc <<-PUPPETCODE
      Used with NFQUEUE jump target.
      What queue number to send packets to
    PUPPETCODE
    munge do |value|
      match = value.to_s.match('^([0-9])*$')
      if match.nil?
        raise ArgumentError, 'queue_num must be an integer'
      end

      if match[1].to_i > 65_535 || match[1].to_i < 0
        raise ArgumentError, 'queue_num must be between 0 and 65535'
      end
      value
    end
  end

  newproperty(:queue_bypass, required_features: :queue_bypass) do
    desc <<-PUPPETCODE
      Used with NFQUEUE jump target
      Allow packets to bypass :queue_num if userspace process is not listening
    PUPPETCODE
    newvalues(:true, :false)
  end

  newproperty(:src_cc) do
    desc <<-PUPPETCODE
      src attribute for the module geoip
    PUPPETCODE
    newvalues(%r{^[A-Z]{2}(,[A-Z]{2})*$})
  end

  newproperty(:dst_cc) do
    desc <<-PUPPETCODE
      dst attribute for the module geoip
    PUPPETCODE
    newvalues(%r{^[A-Z]{2}(,[A-Z]{2})*$})
  end

  newproperty(:hashlimit_name) do
    desc <<-PUPPETCODE
      The name for the /proc/net/ipt_hashlimit/foo entry.
      This parameter is required.
    PUPPETCODE
  end

  newproperty(:hashlimit_upto) do
    desc <<-PUPPETCODE
      Match if the rate is below or equal to amount/quantum. It is specified either as a number, with an optional time quantum suffix (the default is 3/hour), or as amountb/second (number of bytes per second).
      This parameter or hashlimit_above is required.
      Allowed forms are '40','40/second','40/minute','40/hour','40/day'.
    PUPPETCODE
  end

  newproperty(:hashlimit_above) do
    desc <<-PUPPETCODE
      Match if the rate is above amount/quantum.
      This parameter or hashlimit_upto is required.
      Allowed forms are '40','40/second','40/minute','40/hour','40/day'.
    PUPPETCODE
  end

  newproperty(:hashlimit_burst) do
    desc <<-PUPPETCODE
      Maximum initial number of packets to match: this number gets recharged by one every time the limit specified above is not reached, up to this number; the default is 5. When byte-based rate matching is requested, this option specifies the amount of bytes that can exceed the given rate. This option should be used with caution -- if the entry expires, the burst value is reset too.
    PUPPETCODE
    newvalue(%r{^\d+$})
  end

  newproperty(:hashlimit_mode) do
    desc <<-PUPPETCODE
      A comma-separated list of objects to take into consideration. If no --hashlimit-mode option is given, hashlimit acts like limit, but at the expensive of doing the hash housekeeping.
      Allowed values are: srcip, srcport, dstip, dstport
    PUPPETCODE
  end

  newproperty(:hashlimit_srcmask) do
    desc <<-PUPPETCODE
      When --hashlimit-mode srcip is used, all source addresses encountered will be grouped according to the given prefix length and the so-created subnet will be subject to hashlimit. prefix must be between (inclusive) 0 and 32. Note that --hashlimit-srcmask 0 is basically doing the same thing as not specifying srcip for --hashlimit-mode, but is technically more expensive.
    PUPPETCODE
  end

  newproperty(:hashlimit_dstmask) do
    desc <<-PUPPETCODE
      Like --hashlimit-srcmask, but for destination addresses.
    PUPPETCODE
  end

  newproperty(:hashlimit_htable_size) do
    desc <<-PUPPETCODE
      The number of buckets of the hash table
    PUPPETCODE
  end

  newproperty(:hashlimit_htable_max) do
    desc <<-PUPPETCODE
      Maximum entries in the hash.
    PUPPETCODE
  end

  newproperty(:hashlimit_htable_expire) do
    desc <<-PUPPETCODE
      After how many milliseconds do hash entries expire.
    PUPPETCODE
  end

  newproperty(:hashlimit_htable_gcinterval) do
    desc <<-PUPPETCODE
      How many milliseconds between garbage collection intervals.
    PUPPETCODE
  end

  newproperty(:bytecode, required_features: :iptables) do
    desc <<-PUPPETCODE
      Match using Linux Socket Filter. Expects a BPF program in decimal format.
      This is the format generated by the nfbpf_compile utility.
    PUPPETCODE
  end

  newproperty(:ipvs, required_features: :ipvs) do
    desc <<-PUPPETCODE
      Indicates that the current packet belongs to an IPVS connection.
    PUPPETCODE
    newvalues(:true, :false)
  end

  newproperty(:zone, required_features: :ct_target) do
    desc <<-PUPPETCODE
      Assign this packet to zone id and only have lookups done in that zone.
    PUPPETCODE
  end

  newproperty(:helper, required_features: :ct_target) do
    desc <<-PUPPETCODE
      Invoke the nf_conntrack_xxx helper module for this packet.
    PUPPETCODE
  end

  newproperty(:cgroup) do
    desc <<-PUPPETCODE
      Matches against the net_cls cgroup ID of the packet.
    PUPPETCODE
  end

  newproperty(:notrack, required_features: :ct_target) do
    # use this parameter with latest version of iptables
    desc <<-PUPPETCODE
     Invoke the disable connection tracking for this packet.
     This parameter can be used with iptables version >= 1.8.3
    PUPPETCODE
    newvalues(:true, :false)
  end

  newproperty(:condition, required_features: :condition) do
    desc <<-PUPPETCODE
      Match on boolean value (0/1) stored in /proc/net/nf_condition/name.
    PUPPETCODE
    validate do |value|
      unless value.is_a?(String)
        raise ArgumentError, <<-PUPPETCODE
          Condition must be a string.
        PUPPETCODE
      end
    end
  end

  autorequire(:firewallchain) do
    reqs = []
    protocol = nil

    case value(:provider)
    when :iptables
      protocol = 'IPv4'
    when :ip6tables
      protocol = 'IPv6'
    end

    unless protocol.nil?
      table = value(:table)
      main_chains = ['INPUT', 'OUTPUT', 'FORWARD']
      [value(:chain), value(:jump)].each do |chain|
        reqs << "#{chain}:#{table}:#{protocol}" unless chain.nil? || (main_chains.include?(chain) && table == :filter)
      end
    end

    reqs
  end

  # Classes would be a better abstraction, pending:
  # http://projects.puppetlabs.com/issues/19001
  autorequire(:package) do
    case value(:provider)
    when :iptables, :ip6tables
      ['iptables', 'iptables-persistent', 'iptables-services']
    else
      []
    end
  end

  autorequire(:service) do
    case value(:provider)
    when :iptables, :ip6tables
      ['firewalld', 'iptables', 'ip6tables', 'iptables-persistent', 'netfilter-persistent']
    else
      []
    end
  end

  # On RHEL 7 this needs to be threaded correctly to manage SE Linux permissions after persisting the rules
  autobefore(:file) do
    ['/etc/sysconfig/iptables', '/etc/sysconfig/ip6tables']
  end

  validate do
    debug('[validate]')

    # TODO: this is put here to skip validation if ensure is not set. This
    # is because there is a revalidation stage called later where the values
    # are not set correctly. I tried tracing it - but have put in this
    # workaround instead to skip. Must get to the bottom of this.
    unless value(:ensure)
      return
    end

    # First we make sure the chains and tables are valid combinations
    if value(:table).to_s == 'filter' &&
       value(:chain) =~ %r{PREROUTING|POSTROUTING}

      raise "PREROUTING and POSTROUTING cannot be used in table 'filter'"
    end

    if value(:table).to_s == 'nat' && value(:chain) =~ %r{INPUT|FORWARD}
      raise "INPUT and FORWARD cannot be used in table 'nat'"
    end

    if value(:table).to_s == 'raw' &&
       value(:chain) =~ %r{INPUT|FORWARD|POSTROUTING}

      raise 'INPUT, FORWARD and POSTROUTING cannot be used in table raw'
    end

    # Now we analyse the individual properties to make sure they apply to
    # the correct combinations.
    if value(:uid)
      unless %r{OUTPUT|POSTROUTING}.match?(value(:chain).to_s)
        raise 'Parameter uid only applies to chains ' \
          'OUTPUT,POSTROUTING'
      end
    end

    if value(:gid)
      unless %r{OUTPUT|POSTROUTING}.match?(value(:chain).to_s)
        raise 'Parameter gid only applies to chains ' \
          'OUTPUT,POSTROUTING'
      end
    end

    if value(:set_mark)
      unless value(:jump).to_s.include?('MARK') &&
             value(:table).to_s.include?('mangle')
        raise 'Parameter set_mark only applies to ' \
          'the mangle table and when jump => MARK'
      end
    end

    if value(:dport)
      unless %r{tcp|udp|sctp}.match?(value(:proto).to_s)
        raise '[%s] Parameter dport only applies to sctp, tcp and udp ' \
          'protocols. Current protocol is [%s] and dport is [%s]' %
              [value(:name), should(:proto), should(:dport)]
      end
    end

    if value(:jump).to_s == 'DSCP'
      unless value(:set_dscp) || value(:set_dscp_class)
        raise 'When using jump => DSCP, the set_dscp or set_dscp_class property is required'
      end
    end

    if value(:jump).to_s == 'TCPMSS'
      unless value(:set_mss) || value(:clamp_mss_to_pmtu)
        raise 'When using jump => TCPMSS, the set_mss or clamp_mss_to_pmtu property is required'
      end
    end

    if value(:jump).to_s == 'TEE'
      unless value(:gateway)
        raise 'When using jump => TEE, the gateway property is required'
      end
    end

    if value(:jump).to_s == 'DNAT'
      unless %r{nat}.match?(value(:table).to_s)
        raise 'Parameter jump => DNAT only applies to table => nat'
      end

      unless value(:todest)
        raise 'Parameter jump => DNAT must have todest parameter'
      end
    end

    if value(:jump).to_s == 'SNAT'
      unless %r{nat}.match?(value(:table).to_s)
        raise 'Parameter jump => SNAT only applies to table => nat'
      end

      unless value(:tosource)
        raise 'Parameter jump => SNAT must have tosource parameter'
      end
    end

    if value(:jump).to_s == 'MASQUERADE'
      unless %r{nat}.match?(value(:table).to_s)
        raise 'Parameter jump => MASQUERADE only applies to table => nat'
      end
    end

    if value(:log_prefix) || value(:log_level) || value(:log_uid) ||
       value(:log_tcp_sequence) || value(:log_tcp_options) || value(:log_ip_options) == :true
      unless value(:jump).to_s == 'LOG'
        raise 'Parameter log_prefix, log_level, log_tcp_sequence, log_tcp_options, log_ip_options  and log_uid require jump => LOG'
      end
    end

    if value(:burst) && !value(:limit)
      raise 'burst makes no sense without limit'
    end

    if value(:action) && value(:jump)
      raise "Only one of the parameters 'action' and 'jump' can be set"
    end

    if value(:connlimit_mask) && !value(:connlimit_above)
      raise "Parameter 'connlimit_mask' requires 'connlimit_above'"
    end

    if value(:mask) && !value(:recent)
      raise 'Mask can only be set if recent is enabled.'
    end

    [:stat_packet, :stat_every, :stat_probability].each do |param|
      if value(param) && !value(:stat_mode)
        raise "Parameter '#{param}' requires 'stat_mode' to be set"
      end
    end

    if value(:stat_packet) && value(:stat_mode) != :nth
      raise "Parameter 'stat_packet' requires 'stat_mode' to be set to 'nth'"
    end

    if value(:stat_every) && value(:stat_mode) != :nth
      raise "Parameter 'stat_every' requires 'stat_mode' to be set to 'nth'"
    end

    if value(:stat_probability) && value(:stat_mode) != :random
      raise "Parameter 'stat_probability' requires 'stat_mode' to be set to 'random'"
    end

    if value(:checksum_fill) == :true
      unless value(:jump).to_s == 'CHECKSUM' && value(:table).to_s == 'mangle'
        raise 'Parameter checksum_fill requires jump => CHECKSUM and table => mangle'
      end
    end

    if value(:queue_num) || value(:queue_bypass) == :true
      unless value(:jump).to_s == 'NFQUEUE'
        raise 'Paramter queue_number and queue_bypass require jump => NFQUEUE'
      end
    end

    if value(:hashlimit_name)
      unless value(:hashlimit_upto) || value(:hashlimit_above)
        raise 'Either hashlimit_upto or hashlimit_above are required'
      end
    end

    if value(:zone)
      unless value(:jump).to_s == 'CT'
        raise 'Parameter zone requires jump => CT'
      end
    end

    if value(:helper)
      unless value(:jump).to_s == 'CT'
        raise 'Parameter helper requires jump => CT'
      end
    end

    if value(:notrack)
      unless value(:jump).to_s == 'CT'
        raise 'Parameter notrack requires jump => CT'
      end
    end

    if value(:jump).to_s == 'CT'
      unless %r{raw}.match?(value(:table).to_s)
        raise 'Parameter jump => CT only applies to table => raw'
      end
    end
  end
end
