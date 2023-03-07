# lib/puppet/type/iptables.rb
require 'puppet/resource_api'

Puppet::ResourceApi.register_type(
  name: 'iptables',
  docs: <<-EOS,
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
  EOS
  attributes: {
    ensure: {
      type:    "Enum[present, absent, 'present', 'absent']",
      default: 'present',
      desc:    <<-EOS
      Whether this rule should be present or absent on the target system.
      EOS
    },
    name: {
      type:      'Pattern[/(^\d+(?:[ \t]\S+)+$)/]',
      behaviour: :namevar,
      desc:      <<-EOS
      The canonical name of the rule. This name is also used for ordering
      so make sure you prefix the rule with a number:

          000 this runs first
          999 this runs last

      Depending on the provider, the name of the rule can be stored using
      the comment feature of the underlying firewall subsystem.
      EOS
    },
    chain: {
      type:    'Pattern[/(^(.+):(nat|mangle|filter|raw|rawpost|broute|security):(IP(v[46])?|ethernet))|INPUT|OUTPUT|FORWARD|PREROUTING|POSTROUTING$/]',
      default: 'INPUT',
      desc:    <<-EOS
      Name of the chain to use. Can be one of the built-ins:

      * INPUT
      * FORWARD
      * OUTPUT
      * PREROUTING
      * POSTROUTING

      Or you can provide a user-based chain.
      EOS
    },
    proto: {
      type:    "Enum[ip, tcp, udp, icmp, esp, ah, vrrp, carp, igmp, ipencap, ipv4, ospf, gre, cbt, sctp, pim, all, '! ip', '! tcp', '! udp', '! icmp', '! esp', '! ah', '! vrrp', '! carp', '! igmp', '! ipencap', '! ipv4', '! ospf', '! gre', '! cbt', '! sctp', '! pim', '! all']",
      default: 'tcp',
      desc:    <<-EOS
      The specific protocol to match for this rule.
      EOS
    },
    jump: {
      type:    "Enum['ACCEPT', 'REJECT', 'DROP', 'QUEUE', 'RETURN', 'DNAT', 'SNAT', 'LOG', 'NFLOG', 'MASQUERADE', 'REDIRECT', 'MARK', 'CT']",
      default: 'accept',
      desc:    <<-EOS
      This value for the iptables --jump parameter and the action to perform on a match. Generic values are:

      * accept - the packet is accepted
      * reject - the packet is rejected with a suitable ICMP response
      * drop - the packet is dropped

      Can also be on of the following:

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

      If you specify no value it will simply match the rule but perform no
      action.
      EOS
    },
    sport: {
      type:    'Optional[Variant[Array[Pattern[/^(?:!\s)?\d+(?:-\d+)?$/]],Pattern[/^(?:!\s)?\d+(?:-\d+)?$/]]]',
      desc:    <<-EOS
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

      Note: this will negate all passed ports, it is not possible to negate a single one of the array. 
      EOS
    },
    dport: {
      type:    'Optional[Variant[Array[Pattern[/^(?:!\s)?\d+(?:-\d+)?$/]],Pattern[/^(?:!\s)?\d+(?:-\d+)?$/]]]',
      desc:    <<-EOS
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

      Note: this will negate all passed ports, it is not possible to negate a single one of the array. 
      EOS
    },
    source: {
      type:    'Optional[Pattern[/^(?:!\s)?\d+\.\d+\.\d+\.\d+\/\d+$/]]',
      desc:    <<-EOS
      The source address. For example:

          source => '192.168.2.0/24'

      You can also negate a mask by putting ! in front. For example:

          source => '! 192.168.2.0/24'

      The source can also be an IPv6 address if your provider supports it.
      EOS
    },
    destination: {
      type:    'Optional[Pattern[/^(?:!\s)?\d+\.\d+\.\d+\.\d+\/\d+$/]]',
      desc:    <<-EOS
      The destination address to match. For example:

          destination => '192.168.1.0/24'

      You can also negate a mask by putting ! in front. For example:

          destination  => '! 192.168.2.0/24'

      The destination can also be an IPv6 address if your provider supports it.
      EOS
    },
  },
)