# frozen_string_literal: true

# lib/puppet/type/iptables.rb
require 'puppet/resource_api'

Puppet::ResourceApi.register_type(
  name: 'firewall',
  docs: <<-DESC,
  This type provides the capability to manage firewall rules within puppet via iptables.

  **Autorequires:**

  If Puppet is managing the iptables chains specified in the
  `chain` or `jump` parameters, the firewall resource will autorequire
  those firewallchain resources.

  If Puppet is managing the iptables, iptables-persistent, or iptables-services packages,
  the firewall resource will autorequire those packages to ensure that any required binaries are
  installed.

  #### Providers
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
  DESC
  features: ['custom_insync'],
  attributes: {
    ensure: {
      type: "Enum[present, absent, 'present', 'absent']",
      default: 'present',
      desc: <<-DESC
      Whether this rule should be present or absent on the target system.
      DESC
    },
    name: {
      type: 'Pattern[/(^\d+(?:[ \t-]\S+)+$)/]',
      behaviour: :namevar,
      desc: <<-DESC
      The canonical name of the rule. This name is also used for ordering
      so make sure you prefix the rule with a number:

          000 this runs first
          999 this runs last

      Depending on the provider, the name of the rule can be stored using
      the comment feature of the underlying firewall subsystem.
      DESC
    },
    line: {
      type: 'Optional[String[1]]',
      behaviour: :read_only,
      desc: <<-DESC
      A read only attribute containing the full rule, used when deleting and when applying firewallchain purge attributes.
      DESC
    },
    protocol: {
      type: "Enum['iptables', 'ip6tables', 'IPv4', 'IPv6']",
      default: 'IPv4',
      desc: <<-DESC
      The protocol used to set the rule, it's allowed values have been expanded to bring it closer to its `firewallchain` counterpart.
      Defaults to `IPv4`

      Noted: this was previously defined as `provider`, however the resource_api does not allow this to be used as an attribute title.
      DESC
    },
    table: {
      type: "Enum['nat', 'mangle', 'filter', 'raw', 'rawpost', 'broute', 'security']",
      default: 'filter',
      desc: <<-DESC
      The table the rule will exist in.
      Valid options are:

      * nat
      * mangle
      * filter
      * raw
      * rawpost

      Defaults to 'filter'
      DESC
    },
    chain: {
      type: 'String[1]',
      default: 'INPUT',
      desc: <<-DESC
      Name of the chain the rule will be a part of, ensure the chain you choose exists within your set table.
      Can be one of the built-in chains:

      * INPUT
      * FORWARD
      * OUTPUT
      * PREROUTING
      * POSTROUTING

      Or you can provide a user-based chain.
      Defaults to 'INPUT'
      DESC
    },
    source: {
      type: 'Optional[String[1]]',
      desc: <<-DESC
      The source address. For example:

          source => '192.168.2.0/24'

      You can also negate a mask by putting ! in front. For example:

          source => '! 192.168.2.0/24'

      The source can also be an IPv6 address if your provider supports it.
      DESC
    },
    destination: {
      type: 'Optional[String[1]]',
      desc: <<-DESC
      The destination address to match. For example:

          destination => '192.168.1.0/24'

      You can also negate a mask by putting ! in front. For example:

          destination  => '! 192.168.2.0/24'

      The destination can also be an IPv6 address if your provider supports it.
      DESC
    },
    iniface: {
      type: 'Optional[Pattern[/^(?:!\s)?[a-zA-Z0-9\-\._\+\:@]+$/]]',
      desc: <<-DESC
      Input interface to filter on.  Supports interface alias like eth0:0.
      To negate the match try this:

            iniface => '! lo',
      DESC
    },
    outiface: {
      type: 'Optional[Pattern[/^(?:!\s)?[a-zA-Z0-9\-\._\+\:@]+$/]]',
      desc: <<-DESC
      Output interface to filter on.  Supports interface alias like eth0:0.
      To negate the match try this:

            outiface => '! lo',
      DESC
    },
    physdev_in: {
      type: 'Optional[Pattern[/^(?:!\s)?[a-zA-Z0-9\-\._\+]+$/]]',
      desc: <<-DESC
      Match if the packet is entering a bridge from the given interface.
      To negate the match try this:

          physdev_in => '! lo',
      DESC
    },
    physdev_out: {
      type: 'Optional[Pattern[/^(?:!\s)?[a-zA-Z0-9\-\._\+]+$/]]',
      desc: <<-DESC
      Match if the packet is leaving a bridge via the given interface.
      To negate the match try this:

          physdev_out => '! lo',
      DESC
    },
    physdev_is_bridged: {
      type: 'Optional[Boolean]',
      desc: <<-DESC
      Match if the packet is transversing a bridge.
      DESC
    },
    physdev_is_in: {
      type: 'Optional[Boolean]',
      desc: <<-DESC
      Matches if the packet has entered through a bridge interface.
      DESC
    },
    physdev_is_out: {
      type: 'Optional[Boolean]',
      desc: <<-DESC
      Matches if the packet will leave through a bridge interface.
      DESC
    },
    proto: {
      type: 'Optional[Pattern[/^(?:!\s)?(?:ip(?:encap)?|tcp|udp|icmp|esp|ah|vrrp|carp|igmp|ipv4|ospf|gre|cbt|sctp|pim|all)/]]',
      default: 'tcp',
      desc: <<-DESC
      The specific protocol to match for this rule.
      DESC
    },
    isfragment: {
      type: 'Optional[Boolean]',
      desc: <<-DESC
      Set to true to match tcp fragments (requires proto to be set to tcp)
      DESC
    },
    isfirstfrag: {
      type: 'Optional[Boolean]',
      desc: <<-DESC
      Matches if the packet is the first fragment.
      Specific to IPv6.
      DESC
    },
    ishasmorefrags: {
      type: 'Optional[Boolean]',
      desc: <<-DESC
      Matches if the packet has it's 'more fragments' bit set.
      Specific to IPv6.
      DESC
    },
    islastfrag: {
      type: 'Optional[Boolean]',
      desc: <<-DESC
      Matches if the packet is the last fragment.
      Specific to IPv6.
      DESC
    },
    stat_mode: {
      type: 'Optional[Enum[nth, random]]',
      desc: <<-DESC
      Set the matching mode for statistic matching.
      DESC
    },
    stat_every: {
      type: 'Optional[Integer[1]]',
      desc: <<-DESC
      Match one packet every nth packet. Requires `stat_mode => 'nth'`
      DESC
    },
    stat_packet: {
      type: 'Optional[Integer]',
      desc: <<-DESC
      Set the initial counter value for the nth mode. Must be between 0 and the value of `stat_every`.
      Defaults to 0. Requires `stat_mode => 'nth'`
      DESC
    },
    stat_probability: {
      type: 'Optional[Variant[Integer[0,1], Float[0.0,1.0]]]',
      desc: <<-DESC
      Set the probability from 0 to 1 for a packet to be randomly matched. It works only with `stat_mode => 'random'`.
      DESC
    },
    src_range: {
      type: 'Optional[String[1]]',
      desc: <<-DESC
      The source IP range. For example:

          src_range => '192.168.1.1-192.168.1.10'

      You can also negate the range by apending a `!`` to the front. For example:

          src_range => '! 192.168.1.1-192.168.1.10'

      The source IP range must be in 'IP1-IP2' format.
      DESC
    },
    dst_range: {
      type: 'Optional[String[1]]',
      desc: <<-DESC
      The destination IP range. For example:

          dst_range => '192.168.1.1-192.168.1.10'

      You can also negate the range by putting ! in front. For example:

          dst_range => '! 192.168.1.1-192.168.1.10'

      The destination IP range must be in 'IP1-IP2' format.
      DESC
    },
    tcp_option: {
      type: 'Optional[Variant[Pattern[/^(?:!\s)?(?:[0-1][0-9]{0,2}|2[0-4][0-9]|25[0-5])$/], Integer[0,255]]]',
      desc: <<-DESC
      Match when the TCP option is present or absent.
      Given as a single TCP option, optionally prefixed with '! ' to match
      on absence instead.  Only one TCP option can be matched in a given rule.
      TCP option numbers are an eight-bit field, so valid option numbers range
      from 0-255.
      DESC
    },
    tcp_flags: {
      type: 'Optional[Pattern[/^(?:!\s)?((FIN|SYN|RST|PSH|ACK|URG|ALL|NONE),?)+\s((FIN|SYN|RST|PSH|ACK|URG|ALL|NONE),?)+$/]]',
      desc: <<-DESC
      Match when the TCP flags are as specified.
      Is a string with a list of comma-separated flag names for the mask,
      then a space, then a comma-separated list of flags that should be set.
      The flags are: FIN SYN RST PSH ACK URG ALL NONE
      Note that you specify them in the order that iptables --list-rules
      would list them to avoid having puppet think you changed the flags.

      Example: FIN,SYN,RST,ACK SYN matches packets with the SYN bit set and the
      ACK,RST and FIN bits cleared. Such packets are used to request
      TCP  connection initiation.
      Can be negated by placing ! in front, i.e.
        ! FIN,SYN,RST,ACK SYN
      DESC
    },
    uid: {
      type: 'Optional[Variant[String[1], Integer]]',
      desc: <<-DESC
      UID or Username owner matching rule.  Accepts a single argument
      only, as iptables does not accept multiple uid in a single
      statement.
      To negate add a space seperated '!' in front of the value.
      DESC
    },
    gid: {
      type: 'Optional[Variant[String[1], Integer]]',
      desc: <<-DESC
      GID or Group owner matching rule.  Accepts a single argument
      only, as iptables does not accept multiple gid in a single
      statement.
      To negate add a space seperated '!' in front of the value.
      DESC
    },
    mac_source: {
      type: 'Optional[Pattern[/^(?:!\s)?([0-9a-fA-F]{2}[:]){5}([0-9a-fA-F]{2})$/]]',
      desc: <<-DESC
      MAC Source
      DESC
    },
    sport: {
      type: 'Optional[Variant[Array[Variant[Pattern[/^(?:!\s)?\d+(?:(?:\:|-)\d+)?$/],Integer]],Pattern[/^(?:!\s)?\d+(?:(?:\:|-)\d+)?$/],Integer]]',
      desc: <<-DESC
      The source port to match for this filter (if the protocol supports
      ports). Will accept a single element or an array.

      For some firewall providers you can pass a range of ports in the format:

          sport => '1:1024'

      This would cover ports 1 to 1024.

      You can also negate a port by putting ! in front. For example:

          sport => '! 54'

      If you wish to negate multiple ports at once, then place a ! at the start of the first array
      variable. For example:

          sport => ['! 54','23']

      Note:
        This will negate all passed ports, it is not possible to negate a single one of the array.
        In order to maintain compatibility it is also possible to negate all values given in the array to achieve the same behaviour.
      DESC
    },
    dport: {
      type: 'Optional[Variant[Array[Variant[Pattern[/^(?:!\s)?\d+(?:(?:\:|-)\d+)?$/],Integer]],Pattern[/^(?:!\s)?\d+(?:(?:\:|-)\d+)?$/],Integer]]',
      desc: <<-DESC
      The source port to match for this filter (if the protocol supports
      ports). Will accept a single element or an array.

      For some firewall providers you can pass a range of ports in the format:

          dport => '1:1024'

      This would cover ports 1 to 1024.

      You can also negate a port by putting ! in front. For example:

          dport => '! 54'

      If you wish to negate multiple ports at once, then place a ! at the start of the first array
      variable. For example:

          dport => ['! 54','23']

      Note:
        This will negate all passed ports, it is not possible to negate a single one of the array.
        In order to maintain compatibility it is also possible to negate all values given in the array to achieve the same behaviour.
      DESC
    },
    src_type: {
      type: 'Optional[Variant[
             Array[Pattern[/^(?:!\s)?(?:UNSPEC|UNICAST|LOCAL|BROADCAST|ANYCAST|MULTICAST|BLACKHOLE|UNREACHABLE|UNREACHABLE|PROHIBIT|THROW|NAT|XRESOLVE)(?:\s--limit-iface-(?:in|out))?$/]],
             Pattern[/^(?:!\s)?(?:UNSPEC|UNICAST|LOCAL|BROADCAST|ANYCAST|MULTICAST|BLACKHOLE|UNREACHABLE|UNREACHABLE|PROHIBIT|THROW|NAT|XRESOLVE)(?:\s--limit-iface-(?:in|out))?$/]]]',
      desc: <<-DESC
      The source address type. For example:

          src_type => 'LOCAL'

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

      Will accept a single element or an array. Each element of the array should be negated seperately.
      DESC
    },
    dst_type: {
      type: 'Optional[Variant[
             Array[Pattern[/^(?:!\s)?(?:UNSPEC|UNICAST|LOCAL|BROADCAST|ANYCAST|MULTICAST|BLACKHOLE|UNREACHABLE|UNREACHABLE|PROHIBIT|THROW|NAT|XRESOLVE)(?:\s--limit-iface-(?:in|out))?$/]],
             Pattern[/^(?:!\s)?(?:UNSPEC|UNICAST|LOCAL|BROADCAST|ANYCAST|MULTICAST|BLACKHOLE|UNREACHABLE|UNREACHABLE|PROHIBIT|THROW|NAT|XRESOLVE)(?:\s--limit-iface-(?:in|out))?$/]]]',
      desc: <<-DESC
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

      Each value can be negated seperately using '!':

          dst_type => ['! UNICAST', '! LOCAL']

      Will accept a single element or an array.
      DESC
    },
    socket: {
      type: 'Optional[Boolean]',
      desc: <<-DESC
      If true, matches if an open socket can be found by doing a coket lookup
      on the packet.
      DESC
    },
    pkttype: {
      type: "Optional[Enum['unicast', 'broadcast', 'multicast']]",
      desc: <<-DESC
      Sets the packet type to match.
      DESC
    },
    ipsec_dir: {
      type: "Optional[Enum['in', 'out']]",
      desc: <<-DESC
      Sets the ipsec policy direction
      DESC
    },
    ipsec_policy: {
      type: "Optional[Enum['none', 'ipsec']]",
      desc: <<-DESC
      Sets the ipsec policy type. May take a combination of arguments for any flags that can be passed to `--pol ipsec` such as: `--strict`, `--reqid 100`, `--next`, `--proto esp`, etc.
      DESC
    },
    state: {
      type: 'Optional[Variant[Pattern[/^(?:!\s)?(?:INVALID|ESTABLISHED|NEW|RELATED|UNTRACKED)$/], Array[Pattern[/^(?:!\s)?(?:INVALID|ESTABLISHED|NEW|RELATED|UNTRACKED)$/]]]]',
      desc: <<-DESC
      Matches a packet based on its state in the firewall stateful inspection
      table. Values can be:

      * INVALID
      * ESTABLISHED
      * NEW
      * RELATED
      * UNTRACKED
      * SNAT
      * DNAT

      Can be passed either as a single String or as an Array:

          state => 'INVALID'
          state => ['INVALID', 'ESTABLISHED']

      Values can be negated by adding a '!'.
      If you wish to negate multiple states at once, then place a ! at the start of the first array
      variable. For example:

          state => ['! INVALID', 'ESTABLISHED']

      Note:
        This will negate all passed states, it is not possible to negate a single one of the array.
        In order to maintain compatibility it is also possible to negate all values given in the array to achieve the same behaviour.
      DESC
    },
    ctmask: {
      type: 'Optional[String]',
      desc: <<-DESC
      ctmask
      DESC
    },
    nfmask: {
      type: 'Optional[String]',
      desc: <<-DESC
      nfmask
      DESC
    },
    ctstate: {
      type: 'Optional[Variant[Pattern[/^(?:!\s)?(?:INVALID|ESTABLISHED|NEW|RELATED|UNTRACKED|SNAT|DNAT)$/], Array[Pattern[/^(?:!\s)?(?:INVALID|ESTABLISHED|NEW|RELATED|UNTRACKED|SNAT|DNAT)$/]]]]',
      desc: <<-DESC
      Matches a packet based on its state in the firewall stateful inspection
      table, using the conntrack module. Values can be:

      * INVALID
      * ESTABLISHED
      * NEW
      * RELATED
      * UNTRACKED
      * SNAT
      * DNAT

      Can be passed either as a single String or as an Array, if passed as an array values should be passed in order:

          ctstate => 'INVALID'
          ctstate => ['INVALID', 'ESTABLISHED']

      Values can be negated by adding a '!'.
      If you wish to negate multiple states at once, then place a ! at the start of the first array
      variable. For example:

      ctstate => ['! INVALID', 'ESTABLISHED']

      Note:
        This will negate all passed states, it is not possible to negate a single one of the array.
        In order to maintain compatibility it is also possible to negate all values given in the array to achieve the same behaviour.
      DESC
    },
    ctproto: {
      type: 'Optional[Variant[Pattern[/^(?:!\s)?\d+$/],Integer]]',
      desc: <<-DESC
      The specific layer-4 protocol number to match for this rule using the
      conntrack module.
      DESC
    },
    ctorigsrc: {
      type: 'Optional[String[1]]',
      desc: <<-DESC
      The original source address using the conntrack module. For example:

          ctorigsrc => '192.168.2.0/24'

      You can also negate a mask by putting ! in front. For example:

          ctorigsrc => '! 192.168.2.0/24'

      The ctorigsrc can also be an IPv6 address if your provider supports it.
      DESC
    },
    ctorigdst: {
      type: 'Optional[String[1]]',
      desc: <<-DESC
      The original destination address using the conntrack module. For example:

          ctorigdst => '192.168.2.0/24'

      You can also negate a mask by putting ! in front. For example:

          ctorigdst => '! 192.168.2.0/24'

      The ctorigdst can also be an IPv6 address if your provider supports it.
      DESC
    },
    ctreplsrc: {
      type: 'Optional[String[1]]',
      desc: <<-DESC
      The reply source address using the conntrack module. For example:

          ctreplsrc => '192.168.2.0/24'

      You can also negate a mask by putting ! in front. For example:

          ctreplsrc => '! 192.168.2.0/24'

      The ctreplsrc can also be an IPv6 address if your provider supports it.
      DESC
    },
    ctrepldst: {
      type: 'Optional[String[1]]',
      desc: <<-DESC
      The reply destination address using the conntrack module. For example:

          ctrepldst => '192.168.2.0/24'

      You can also negate a mask by putting ! in front. For example:

          ctrepldst => '! 192.168.2.0/24'

      The ctrepldst can also be an IPv6 address if your provider supports it.
      DESC
    },
    ctorigsrcport: {
      type: 'Optional[Pattern[/^(?:!\s)?\d+(?:\:\d+)?$/]]',
      desc: <<-DESC
      The original source port to match for this filter using the conntrack module.
      For example:

          ctorigsrcport => '80'

      You can also specify a port range: For example:

          ctorigsrcport => '80:81'

      You can also negate a port by putting ! in front. For example:

          ctorigsrcport => '! 80'
      DESC
    },
    ctorigdstport: {
      type: 'Optional[Pattern[/^(?:!\s)?\d+(?:\:\d+)?$/]]',
      desc: <<-DESC
      The original destination port to match for this filter using the conntrack module.
      For example:

          ctorigdstport => '80'

      You can also specify a port range: For example:

          ctorigdstport => '80:81'

      You can also negate a port by putting ! in front. For example:

          ctorigdstport => '! 80'
      DESC
    },
    ctreplsrcport: {
      type: 'Optional[Pattern[/^(?:!\s)?\d+(?:\:\d+)?$/]]',
      desc: <<-DESC
      The reply source port to match for this filter using the conntrack module.
      For example:

          ctreplsrcport => '80'

      You can also specify a port range: For example:

          ctreplsrcport => '80:81'

      You can also negate a port by putting ! in front. For example:

          ctreplsrcport => '! 80'
      DESC
    },
    ctrepldstport: {
      type: 'Optional[Pattern[/^(?:!\s)?\d+(?:\:\d+)?$/]]',
      desc: <<-DESC
      The reply destination port to match for this filter using the conntrack module.
      For example:

          ctrepldstport => '80'

      You can also specify a port range: For example:

          ctrepldstport => '80:81'

      You can also negate a port by putting ! in front. For example:

          ctrepldstport => '! 80'
      DESC
    },
    ctstatus: {
      type: 'Optional[Variant[Pattern[/^(?:!\s)?(?:EXPECTED|SEEN_REPLY|ASSURED|CONFIRMED|NONE)$/], Array[Pattern[/^(?:!\s)?(?:EXPECTED|SEEN_REPLY|ASSURED|CONFIRMED|NONE)$/]]]]',
      desc: <<-DESC
      Matches a packet based on its status using the conntrack module. Values can be:

      * EXPECTED
      * SEEN_REPLY
      * ASSURED
      * CONFIRMED
      * NONE

      Can be passed either as a single String or as an Array:

        ctstatus => 'EXPECTED'
        ctstatus => ['EXPECTED', 'CONFIRMED']

      Values can be negated by adding a '!'.
      If you wish to negate multiple states at once, then place a ! at the start of the first array
      variable. For example:

        ctstatus => ['! EXPECTED', 'CONFIRMED']

      Note:#{' '}
        This will negate all passed states, it is not possible to negate a single one of the array.
        In order to maintain compatibility it is also possible to negate all values given in the array to achieve the same behaviour.
      DESC
    },
    ctexpire: {
      type: 'Optional[Pattern[/^(?:!\s)?\d+(?:\:\d+)?$/]]',
      desc: <<-DESC
      Matches a packet based on lifetime remaining in seconds or range of seconds
      using the conntrack module. For example:

        ctexpire => '100'
        ctexpire => '100:150'
      DESC
    },
    ctdir: {
      type: "Optional[Enum['REPLY', 'ORIGINAL']]",
      desc: <<-DESC
      Matches a packet that is flowing in the specified direction using the
      conntrack module. If this flag is not specified at all, matches packets
      in both directions. Values can be:

      * REPLY
      * ORIGINAL
      DESC
    },
    hop_limit: {
      type: 'Optional[Variant[Pattern[/^(?:!\s)?\d+$/],Integer]]',
      desc: <<-DESC
      Hop limiting value for matched packets.
      To negate add a space seperated `!` the the beginning of the value
      This is IPv6 specific.
      DESC
    },
    icmp: {
      type: 'Optional[Variant[String[1],Integer]]',
      desc: <<-DESC
      When matching ICMP packets, this is the type of ICMP packet to match.

      A value of "any" is not supported. To achieve this behaviour the
      parameter should simply be omitted or undefined.
      An array of values is also not supported. To match against multiple ICMP
      types, please use separate rules for each ICMP type.
      DESC
    },
    limit: {
      type: 'Optional[Pattern[/^\d+\/(?:sec(?:ond)?|min(?:ute)?|hour|day)$/]]',
      desc: <<-DESC
      Rate limiting value for matched packets. The format is:
      rate/[/second/|/minute|/hour|/day]

      Example values are: '50/sec', '40/min', '30/hour', '10/day'."
      DESC
    },
    burst: {
      type: 'Optional[Integer[1]]',
      desc: <<-DESC
      Rate limiting burst value (per second) before limit checks apply.
      DESC
    },
    length: {
      type: 'Optional[Pattern[/^([0-9]+)(:)?([0-9]+)?$/]]',
      desc: <<-DESC
      Sets the length of layer-3 payload to match.

      Example values are: '500', '5:400'
      DESC
    },
    recent: {
      type: "Optional[Enum['set', 'update', 'rcheck', 'remove', '! set', '! update', '! rcheck', '! remove']]",
      desc: <<-DESC
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
          jump     => 'DROP',
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
          jump        => 'DROP',
          chain       => 'FORWARD',
        }
        ```
      DESC
    },
    rseconds: {
      type: 'Optional[Integer[1]]',
      desc: <<-DESC
      Recent module; used in conjunction with one of `recent => 'rcheck'` or
      `recent => 'update'`. When used, this will narrow the match to only
      happen when the address is in the list and was seen within the last given
      number of seconds.
      DESC
    },
    reap: {
      type: 'Optional[Boolean]',
      desc: <<-DESC
      Recent module; can only be used in conjunction with the `rseconds`
      attribute. When used, this will cause entries older than 'seconds' to be
      purged.  Must be boolean true.
      DESC
    },
    rhitcount: {
      type: 'Optional[Integer[1]]',
      desc: <<-DESC
      Recent module; used in conjunction with `recent => 'update'` or `recent
      => 'rcheck'. When used, this will narrow the match to only happen when
      the address is in the list and packets had been received greater than or
      equal to the given value.
      DESC
    },
    rttl: {
      type: 'Optional[Boolean]',
      desc: <<-DESC
      Recent module; may only be used in conjunction with one of `recent =>
      'rcheck'` or `recent => 'update'`. When used, this will narrow the match
      to only happen when the address is in the list and the TTL of the current
      packet matches that of the packet which hit the `recent => 'set'` rule.
      This may be useful if you have problems with people faking their source
      address in order to DoS you via this module by disallowing others access
      to your site by sending bogus packets to you.  Must be boolean true.
      DESC
    },
    rname: {
      type: 'Optional[String[1]]',
      desc: <<-DESC
      Recent module; The name of the list.
      The recent module defaults this to `DEFAULT` when recent is set
      DESC
    },
    mask: {
      type: 'Optional[Pattern[/^\d+\.\d+\.\d+\.\d+$/]]',
      desc: <<-DESC
      Recent module; sets the mask to use when `recent` is enabled.
      The recent module defaults this to `255.255.255.255` when recent is set
      DESC
    },
    rsource: {
      type: 'Optional[Boolean]',
      desc: <<-DESC
      Recent module; add the source IP address to the list.
      Mutually exclusive with `rdest`
      The recent module defaults this behaviour to true when recent is set.
      DESC
    },
    rdest: {
      type: 'Optional[Boolean]',
      desc: <<-DESC
      Recent module; add the destination IP address to the list.
      Mutually exclusive with `rsource`
      Must be boolean true.
      DESC
    },
    ipset: {
      type: 'Optional[Variant[Pattern[/^(?:!\s)?\w+\s(?:src|dst)(?:,src|,dst)?$/], Array[Pattern[/^(?:!\s)?\w+\s(?:src|dst)(?:,src|,dst)?$/]]]]',
      desc: <<-DESC
      Matches against the specified ipset list.
      Requires ipset kernel module. Will accept a single element or an array.
      The value is the name of the denylist, followed by a space, and then
      'src' and/or 'dst' separated by a comma.
      For example: 'denylist src,dst'
      To negate simply place a space seperated `!` at the beginning of a value.
      Values can de negated independently.
      DESC
    },
    string: {
      type: 'Optional[String[1]]',
      desc: <<-DESC
      String matching feature. Matches the packet against the pattern
      given as an argument.
      To negate, add a space seperated `!` to the beginning of the string.
      DESC
    },
    string_hex: {
      type: 'Optional[Pattern[/^(?:!\s)?\|[a-zA-Z0-9\s]+\|$/]]',
      desc: <<-DESC
      String matching feature. Matches the packet against the pattern
      given as an argument.
      To negate, add a space seperated `!` to the beginning of the string.
      DESC
    },
    string_algo: {
      type: "Optional[Enum['bm', 'kmp']]",
      desc: <<-DESC
      String matching feature, pattern matching strategy.
      DESC
    },
    string_from: {
      type: 'Optional[Integer[1]]',
      desc: <<-DESC
      String matching feature, offset from which we start looking for any matching.
      DESC
    },
    string_to: {
      type: 'Optional[Integer[1]]',
      desc: <<-DESC
      String matching feature, offset up to which we should scan.
      DESC
    },
    jump: {
      type: 'Optional[String[1]]',
      desc: <<-DESC
      This value for the iptables --jump parameter and the action to perform on a match. Common values are:

      * ACCEPT - the packet is accepted
      * REJECT - the packet is rejected with a suitable ICMP response
      * DROP - the packet is dropped

      But can also be one of the following:

      * QUEUE
      * RETURN
      * DNAT
      * SNAT
      * LOG
      * NFLOG
      * NETMAP
      * MASQUERADE
      * REDIRECT
      * MARK
      * CT

      And any valid chain name is also allowed.

      If you specify no value it will simply match the rule but perform no action.
      DESC
    },
    goto: {
      type: 'Optional[String[1]]',
      desc: <<-DESC
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
      DESC
    },
    clusterip_new: {
      type: 'Optional[Boolean]',
      desc: <<-DESC
      Used with the CLUSTERIP jump target.
      Create a new ClusterIP. You always have to set this on the first rule for a given ClusterIP.
      This is IPv4 specific.
      DESC
    },
    clusterip_hashmode: {
      type: "Optional[Enum['sourceip', 'sourceip-sourceport', 'sourceip-sourceport-destport']]",
      desc: <<-DESC
      Used with the CLUSTERIP jump target.
      Specify the hashing mode.
      This is IPv4 specific.
      DESC
    },
    clusterip_clustermac: {
      type: 'Optional[Pattern[/^([0-9a-fA-F]{2}[:]){5}([0-9a-fA-F]{2})$/]]',
      desc: <<-DESC
      Used with the CLUSTERIP jump target.
      Specify the ClusterIP MAC address. Has to be a link-layer multicast address.
      This is IPv4 specific.
      DESC
    },
    clusterip_total_nodes: {
      type: 'Optional[Integer[1]]',
      desc: <<-DESC
      Used with the CLUSTERIP jump target.
      Number of total nodes within this cluster.
      This is IPv4 specific.
      DESC
    },
    clusterip_local_node: {
      type: 'Optional[Integer[1]]',
      desc: <<-DESC
      Used with the CLUSTERIP jump target.
      Specify the random seed used for hash initialization.
      This is IPv4 specific.
      DESC
    },
    clusterip_hash_init: {
      type: 'Optional[String[1]]',
      desc: <<-DESC
      Used with the CLUSTERIP jump target.
      Specify the random seed used for hash initialization.
      This is IPv4 specific.
      DESC
    },
    queue_num: {
      type: 'Optional[Integer[1]]',
      desc: <<-DESC
      Used with NFQUEUE jump target.
      What queue number to send packets to
      DESC
    },
    queue_bypass: {
      type: 'Optional[Boolean]',
      desc: <<-DESC
      Allow packets to bypass :queue_num if userspace process is not listening
      DESC
    },
    nflog_group: {
      type: 'Optional[Integer[1, 65535]]',
      desc: <<-DESC
      Used with the jump target NFLOG.
      The netlink group (0 - 2^16-1) to which packets are (only applicable
      for nfnetlink_log). Defaults to 0.
      DESC
    },
    nflog_prefix: {
      type: 'Optional[String]',
      desc: <<-DESC
      Used with the jump target NFLOG.
      A prefix string to include in the log message, up to 64 characters long,
      useful for distinguishing messages in the logs.
      DESC
    },
    nflog_range: {
      type: 'Optional[Integer[1]]',
      desc: <<-DESC
      Used with the jump target NFLOG.
      This has never worked, use nflog_size instead.
      DESC
    },
    nflog_size: {
      type: 'Optional[Integer[1]]',
      desc: <<-DESC
      Used with the jump target NFLOG.
      The number of bytes to be copied to userspace (only applicable for nfnetlink_log).
      nfnetlink_log instances may specify their own size, this option overrides it.
      DESC
    },
    nflog_threshold: {
      type: 'Optional[Integer[1]]',
      desc: <<-DESC
      Used with the jump target NFLOG.
      Number of packets to queue inside the kernel before sending them to userspace
      (only applicable for nfnetlink_log). Higher values result in less overhead
      per packet, but increase delay until the packets reach userspace. Defaults to 1.
      DESC
    },
    gateway: {
      type: 'Optional[Pattern[/^(\d+.\d+.\d+.\d+|\w+:\w+::\w+)$/]]',
      desc: <<-DESC
      The TEE target will clone a packet and redirect this clone to another
      machine on the local network segment.
      Gateway is the target host's IP.
      DESC
    },
    clamp_mss_to_pmtu: {
      type: 'Optional[Boolean]',
      desc: <<-DESC
      Sets the clamp mss to pmtu flag.
      DESC
    },
    set_mss: {
      type: 'Optional[Integer[1]]',
      desc: <<-DESC
      Sets the TCP MSS value for packets.
      DESC
    },
    set_dscp: {
      type: 'Optional[String[1]]',
      desc: <<-DESC
      Set DSCP Markings.
      DESC
    },
    set_dscp_class: {
      type: "Optional[Enum['af11', 'af12', 'af13', 'af21', 'af22', 'af23', 'af31', 'af32', 'af33', 'af41', 'af42', 'af43', 'cs1', 'cs2', 'cs3', 'cs4', 'cs5', 'cs6', 'cs7', 'ef']]",
      desc: <<-DESC
      This sets the DSCP field according to a predefined DiffServ class.
      DESC
    },
    todest: {
      type: 'Optional[String[1]]',
      desc: <<-DESC
      When using jump => "DNAT" you can specify the new destination address using this paramter.
      Can specify a single new destination IP address or an inclusive range of IP addresses.
      Optionally a port or a port range with a possible follow up baseport can be provided.
      Input structure: [ipaddr[-ipaddr]][:port[-port[/baseport]]]
      DESC
    },
    tosource: {
      type: 'Optional[String[1]]',
      desc: <<-DESC
      When using jump => "SNAT" you can specify the new source address using this paramter.
      Can specify a single new destination IP address or an inclusive range of IP addresses.
      Input structure: [ipaddr[-ipaddr]][:port[-port]]
      DESC
    },
    toports: {
      type: 'Optional[Pattern[/^\d+(?:-\d+)?$/]]',
      desc: <<-DESC
      For REDIRECT/MASQUERADE this is the port that will replace the destination/source port.
      Can specify a single new port or an inclusive range of ports.
      DESC
    },
    to: {
      type: 'Optional[String[1]]',
      desc: <<-DESC
      For NETMAP this will replace the destination IP
      DESC
    },
    checksum_fill: {
      type: 'Optional[Boolean]',
      desc: <<-DESC
      Compute and fill missing packet checksums.
      DESC
    },
    random_fully: {
      type: 'Optional[Boolean]',
      desc: <<-DESC
      When using a jump value of "MASQUERADE", "DNAT", "REDIRECT", or "SNAT" this boolean will enable fully randomized port mapping.
      DESC
    },
    random: {
      type: 'Optional[Boolean]',
      desc: <<-DESC
      When using a jump value of "MASQUERADE", "DNAT", "REDIRECT", or "SNAT" this boolean will enable randomized port mapping.
      DESC
    },
    log_prefix: {
      type: 'Optional[String[1]]',
      desc: <<-DESC
      When combined with jump => "LOG" specifies the log prefix to use when logging.
      DESC
    },
    log_level: {
      type: 'Optional[Variant[Integer[0,7],String[1]]]',
      desc: <<-DESC
      When combined with jump => "LOG" specifies the system log level to log to.

      Note: log level 4/warn is the default setting and as such it is not returned by iptables-save.
      As a result, explicitly setting `log_level` to this can result in idempotency errors.
      DESC
    },
    log_uid: {
      type: 'Optional[Boolean]',
      desc: <<-DESC
      When combined with jump => "LOG" specifies the uid of the process making the connection.
      DESC
    },
    log_tcp_sequence: {
      type: 'Optional[Boolean]',
      desc: <<-DESC
      When combined with jump => "LOG" enables logging of the TCP sequence numbers.
      DESC
    },
    log_tcp_options: {
      type: 'Optional[Boolean]',
      desc: <<-DESC
      When combined with jump => "LOG" logging of the TCP packet header.
      DESC
    },
    log_ip_options: {
      type: 'Optional[Boolean]',
      desc: <<-DESC
      When combined with jump => "LOG" logging of the TCP IP/IPv6 packet header.
      DESC
    },
    reject: {
      type: "Optional[Enum['icmp-net-unreachable', 'icmp-host-unreachable', 'icmp-port-unreachable', 'icmp-proto-unreachable',
                              'icmp-net-prohibited', 'icmp-host-prohibited', 'icmp-admin-prohibited', 'icmp6-no-route', 'no-route',
                              'icmp6-adm-prohibited', 'adm-prohibited', 'icmp6-addr-unreachable', 'addr-unreach', 'icmp6-port-unreachable']]",
      desc: <<-DESC
      When combined with jump => "REJECT" you can specify a different icmp response to be sent back to the packet sender.
      Valid values differ depending on if the protocol is `IPv4` or `IPv6`.
      IPv4 allows: icmp-net-unreachable, icmp-host-unreachable, icmp-port-unreachable, icmp-proto-unreachable, icmp-net-prohibited,
      icmp-host-prohibited, or icmp-admin-prohibited.
      IPv6 allows: icmp6-no-route, no-route, icmp6-adm-prohibited, adm-prohibited, icmp6-addr-unreachable, addr-unreach, or icmp6-port-unreachable.
      DESC
    },
    restore_mark: {
      type: 'Optional[Boolean]',
      desc: <<-DESC
      Whether or not to restore mark.
      DESC
    },
    set_mark: {
      type: 'Optional[Pattern[/^[a-fA-F0-9x]+(?:\/[a-fA-F0-9x]+)?$/]]',
      desc: <<-DESC
      Set the Netfilter mark value associated with the packet.  Accepts either of mark/mask or mark.
      These will be converted to hex if they are not already.
      DESC
    },
    match_mark: {
      type: 'Optional[Pattern[/^(?:!\s)?[a-fA-F0-9x]+$/]]',
      desc: <<-DESC
      Match the Netfilter mark value associated with the packet, accepts a mark.
      This value will be converted to hex if it is not already.
      This value can be negated by adding a space seperated `!` to the beginning.
      DESC
    },
    mss: {
      type: 'Optional[Pattern[/^(?:!\s)?\d+(?:\:\d+)?$/]]',
      desc: <<-DESC
      Match a given TCP MSS value or range.
      This value can be negated by adding a space seperated `!` to the beginning.
      DESC
    },
    connlimit_upto: {
      type: 'Optional[Integer]',
      desc: <<-DESC
      Connection limiting value for matched connections below or equal to n.
      DESC
    },
    connlimit_above: {
      type: 'Optional[Integer]',
      desc: <<-DESC
      Connection limiting value for matched connections above n.
      DESC
    },
    connlimit_mask: {
      type: 'Optional[Integer[0,128]]',
      desc: <<-DESC
      Connection limiting by subnet mask for matched connections.
      IPv4: 0-32
      IPv6: 0-128
      DESC
    },
    connmark: {
      type: 'Optional[Pattern[/^(?:!\s)?[a-fA-F0-9x]+$/]]',
      desc: <<-DESC
      Match the Netfilter mark value associated with the packet, accepts a mark.
      This value will be converted to hex if it is not already.
      This value can be negated by adding a space seperated `!` to the beginning.
      DESC
    },
    time_start: {
      type: 'Optional[Pattern[/^([0-9]|[0-1][0-9]|2[0-3])\:[0-5][0-9](?:\:[0-5][0-9])?/]]',
      desc: <<-DESC
      Only match during the given daytime. The possible time range is 00:00:00 to 23:59:59.
      Leading zeroes are allowed (e.g. "06:03") and correctly interpreted as base-10.
      DESC
    },
    time_stop: {
      type: 'Optional[Pattern[/^([0-9]|[0-1][0-9]|2[0-3])\:[0-5][0-9](?:\:[0-5][0-9])?/]]',
      desc: <<-DESC
      Only match during the given daytime. The possible time range is 00:00:00 to 23:59:59.
      Leading zeroes are allowed (e.g. "06:03") and correctly interpreted as base-10.
      DESC
    },
    month_days: {
      type: 'Optional[Variant[Integer[0,31], Array[Integer[0,31]]]]',
      desc: <<-DESC
      Only match on the given days of the month. Possible values are 1 to 31.
      Note that specifying 31 will of course not match on months which do not have a 31st day;
      the same goes for 28-day or 29-day February.

      Can be passed either as a single value or an array of values:
        month_days => 5,
        month_days => [5, 9, 23],
      DESC
    },
    week_days: {
      type: "Optional[Variant[Enum['Mon','Tue','Wed','Thu','Fri','Sat','Sun'], Array[Enum['Mon','Tue','Wed','Thu','Fri','Sat','Sun']]]]",
      desc: <<-DESC
      Only match on the given weekdays.

      Can be passed either as a single value or an array of values:
        week_days => 'Mon',
        week_days => ['Mon', 'Tue', 'Wed'],
      DESC
    },
    date_start: {
      type: 'Optional[Pattern[/^[0-9]{4}\-(?:0[0-9]|1[0-2])\-(?:[0-2][0-9]|3[0-1])T(?:[0-1][0-9]|2[0-3])\:[0-5][0-9]\:[0-5][0-9]$/]]',
      desc: <<-DESC
      Only match during the given time, which must be in ISO 8601 "T" notation.
      The possible time range is 1970-01-01T00:00:00 to 2038-01-19T04:17:07
      DESC
    },
    date_stop: {
      type: 'Optional[Pattern[/^[0-9]{4}\-(?:0[0-9]|1[0-2])\-(?:[0-2][0-9]|3[0-1])T(?:[0-1][0-9]|2[0-3])\:[0-5][0-9]\:[0-5][0-9]$/]]',
      desc: <<-DESC
      Only match during the given time, which must be in ISO 8601 "T" notation.
      The possible time range is 1970-01-01T00:00:00 to 2038-01-19T04:17:07
      DESC
    },
    time_contiguous: {
      type: 'Optional[Boolean]',
      desc: <<-DESC
      When time_stop is smaller than time_start value, match this as a single time period instead distinct intervals.
      DESC
    },
    kernel_timezone: {
      type: 'Optional[Boolean]',
      desc: <<-DESC
      Use the kernel timezone instead of UTC to determine whether a packet meets the time regulations.
      DESC
    },
    u32: {
      type: 'Optional[Pattern[/^0x[0-9a-fA-F]+&0x[0-9a-fA-F]+=0x[0-9a-fA-F]+(?::0x[0-9a-fA-F]+)?(?:&&0x[0-9a-fA-F]+&0x[0-9a-fA-F]+=0x[0-9a-fA-F]+(?::0x[0-9a-fA-F]+)?)*$/]]',
      desc: <<-DESC
      Enable the u32 module. Takes as an argument one of set, update,
      rcheck or remove. For example:
        firewall { '032 u32 test':
          ensure   => present,
          table    => 'mangle',
          chain    => 'PREROUTING',
          u32      => '0x4&0x1fff=0x0&&0x0&0xf000000=0x5000000',
          jump     => 'DROP',
        }
      DESC
    },
    src_cc: {
      type: 'Optional[Pattern[/^[A-Z]{2}(,[A-Z]{2})*$/]]',
      desc: <<-DESC
      src attribute for the module geoip
      DESC
    },
    dst_cc: {
      type: 'Optional[Pattern[/^[A-Z]{2}(,[A-Z]{2})*$/]]',
      desc: <<-DESC
      dst attribute for the module geoip
      DESC
    },
    hashlimit_upto: {
      type: 'Optional[Pattern[/^\d+(?:\/(?:sec|min|hour|day))?$/]]',
      desc: <<-DESC
      Match if the rate is below or equal to amount/quantum. It is specified either as a number, with an optional time quantum suffix (the default is 3/hour), or as amountb/second (number of bytes per second).
      This parameter or `hashlimit_above` and `hashlimit_name` are required when setting any other hashlimit values.
      Allowed forms are '40','40/sec','40/min','40/hour','40/day'.
      DESC
    },
    hashlimit_above: {
      type: 'Optional[Pattern[/^\d+(?:\/(?:sec|min|hour|day))?$/]]',
      desc: <<-DESC
      Match if the rate is above amount/quantum.
      This parameter or `hashlimit_upto` and `hashlimit_name` are required when setting any other hashlimit values.
      Allowed forms are '40','40/sec','40/min','40/hour','40/day'.
      DESC
    },
    hashlimit_name: {
      type: 'Optional[String[1]]',
      desc: <<-DESC
      The name for the /proc/net/ipt_hashlimit/foo entry.
      This parameter and either `hashlimit_upto` or `hashlimit_above` are required when setting any other hashlimit values.
      DESC
    },
    hashlimit_burst: {
      type: 'Optional[Integer[1]]',
      desc: <<-DESC
      Maximum initial number of packets to match: this number gets recharged by one every time the limit specified above is not reached, up to this number; the default is 5.
      When byte-based rate matching is requested, this option specifies the amount of bytes that can exceed the given rate.
      This option should be used with caution -- if the entry expires, the burst value is reset too.
      DESC
    },
    hashlimit_mode: {
      type: 'Optional[Pattern[/^(?:srcip|srcport|dstip|dstport)(?:\,(?:srcip|srcport|dstip|dstport))*$/]]',
      desc: <<-DESC
      A comma-separated list of objects to take into consideration.
      If no --hashlimit-mode option is given, hashlimit acts like limit, but at the expensive of doing the hash housekeeping.
      Allowed values are: srcip, srcport, dstip, dstport
      DESC
    },
    hashlimit_srcmask: {
      type: 'Optional[Integer[0,32]]',
      desc: <<-DESC
      When --hashlimit-mode srcip is used, all source addresses encountered will be grouped according to the given prefix length
      and the so-created subnet will be subject to hashlimit.
      Prefix must be between (inclusive) 0 and 32.
      Note that --hashlimit-srcmask 0 is basically doing the same thing as not specifying srcip for --hashlimit-mode, but is technically more expensive.
      DESC
    },
    hashlimit_dstmask: {
      type: 'Optional[Integer[0,32]]',
      desc: <<-DESC
      When --hashlimit-mode srcip is used, all destination addresses encountered will be grouped according to the given prefix length
      and the so-created subnet will be subject to hashlimit.
      Prefix must be between (inclusive) 0 and 32.
      Note that --hashlimit-dstmask 0 is basically doing the same thing as not specifying srcip for --hashlimit-mode, but is technically more expensive.
      DESC
    },
    hashlimit_htable_size: {
      type: 'Optional[Integer]',
      desc: <<-DESC
      The number of buckets of the hash table
      DESC
    },
    hashlimit_htable_max: {
      type: 'Optional[Integer]',
      desc: <<-DESC
      Maximum entries in the hash.
      DESC
    },
    hashlimit_htable_expire: {
      type: 'Optional[Integer]',
      desc: <<-DESC
      After how many milliseconds do hash entries expire.
      DESC
    },
    hashlimit_htable_gcinterval: {
      type: 'Optional[Integer]',
      desc: <<-DESC
      How many milliseconds between garbage collection intervals.
      DESC
    },
    bytecode: {
      type: 'Optional[String[1]]',
      desc: <<-DESC
      Match using Linux Socket Filter. Expects a BPF program in decimal format.
      This is the format generated by the nfbpf_compile utility.
      DESC
    },
    ipvs: {
      type: 'Optional[Boolean]',
      desc: <<-DESC
      Match using Linux Socket Filter. Expects a BPF program in decimal format.
      This is the format generated by the nfbpf_compile utility.
      DESC
    },
    zone: {
      type: 'Optional[Integer]',
      desc: <<-DESC
      Assign this packet to zone id and only have lookups done in that zone.
      DESC
    },
    helper: {
      type: 'Optional[String[1]]',
      desc: <<-DESC
      Invoke the nf_conntrack_xxx helper module for this packet.
      DESC
    },
    cgroup: {
      type: 'Optional[String[1]]',
      desc: <<-DESC
      Matches against the net_cls cgroup ID of the packet.

      To negate add a space seperate `!` to the beginning of the string
      DESC
    },
    rpfilter: {
      type: "Optional[Variant[Enum['loose', 'validmark', 'accept-local', 'invert'], Array[Enum['loose', 'validmark', 'accept-local', 'invert']]]]",
      desc: <<-DESC
      Enable the rpfilter module.
      DESC
    },
    condition: {
      type: 'Optional[String[1]]',
      desc: <<-DESC
      Match on boolean value (0/1) stored in /proc/net/nf_condition/name.
      DESC
    },
    notrack: {
      type: 'Optional[Boolean]',
      desc: <<-DESC
      Invoke the disable connection tracking for this packet.
      This parameter can be used with iptables version >= 1.8.3
      DESC
    }
  },
)
