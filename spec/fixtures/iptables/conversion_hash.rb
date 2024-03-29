# These hashes allow us to iterate across a series of test data
# creating rspec examples for each parameter to ensure the input :line
# extrapolates to the desired value for the parameter in question. And
# vice-versa

# This hash is for testing a line conversion to a hash of parameters
# which will be used to create a resource.
ARGS_TO_HASH = {
  'mac_source_1' => {
    line: '-A neutron-openvswi-FORWARD -s 1.2.3.4/32 -m mac --mac-source FA:16:00:00:00:00 -j ACCEPT',
    table: 'filter',
    params: {
      chain: 'neutron-openvswi-FORWARD',
      source: '1.2.3.4/32',
      mac_source: 'FA:16:00:00:00:00',
    },
  },
  'dport_and_sport' => {
    line: '-A nova-compute-FORWARD -s 0.0.0.0/32 -d 255.255.255.255/32 -p udp -m udp --sport 68 --dport 67 -j ACCEPT',
    table: 'filter',
    params: {
      jump: 'accept',
      chain: 'nova-compute-FORWARD',
      source: '0.0.0.0/32',
      destination: '255.255.255.255/32',
      sport: ['68'],
      dport: ['67'],
      proto: 'udp',
    },
  },
  'long_rule_1' => {
    line: '-A INPUT -s 1.1.1.1/32 -d 1.1.1.1/32 -p tcp -m multiport --dports 7061,7062 -m multiport --sports 7061,7062 -j ACCEPT -m comment --comment "000 allow foo"',
    table: 'filter',
    compare_all: true,
    params: {
      jump: 'accept',
      chain: 'INPUT',
      destination: '1.1.1.1/32',
      dport: ['7061', '7062'],
      ensure: :present,
      line: '-A INPUT -s 1.1.1.1/32 -d 1.1.1.1/32 -p tcp -m multiport --dports 7061,7062 -m multiport --sports 7061,7062 -j ACCEPT -m comment --comment "000 allow foo"',
      name: '000 allow foo',
      proto: 'tcp',
      provider: 'iptables',
      source: '1.1.1.1/32',
      sport: ['7061', '7062'],
      table: 'filter',
    },
  },
  'action_drop_1' => {
    line: '-A INPUT -j DROP -m comment --comment "000 allow foo"',
    table: 'filter',
    params: {
      jump: nil,
      jump: 'drop',
    },
  },
  'action_reject_1' => {
    line: '-A INPUT -j REJECT -m comment --comment "000 allow foo"',
    table: 'filter',
    params: {
      jump: nil,
      jump: 'reject',
    },
  },
  'action_nil_1' => {
    line: '-A INPUT -m comment --comment "000 allow foo"',
    table: 'filter',
    params: {
      jump: nil,
      jump: nil,
    },
  },
  'jump_custom_chain_1' => {
    line: '-A INPUT -j custom_chain -m comment --comment "000 allow foo"',
    table: 'filter',
    params: {
      jump: 'custom_chain',
      jump: nil,
    },
  },
  'jump_goto' => {
    line: '-A w--instance-cfmhvrgpmq6 -g w--default',
    table: 'filter',
    params: {
      goto: 'w--default',
      jump: nil,
    },

  },
  'source_destination_ipv4_no_cidr' => {
    line: '-A INPUT -s 1.1.1.1 -d 2.2.2.2 -m comment --comment "000 source destination ipv4 no cidr"',
    table: 'filter',
    params: {
      source: '1.1.1.1/32',
      destination: '2.2.2.2/32',
    },
  },
  'source_destination_ipv6_no_cidr' => {
    line: '-A INPUT -s 2001:db8:85a3::8a2e:370:7334 -d 2001:db8:85a3::8a2e:370:7334 -m comment --comment "000 source destination ipv6 no cidr"',
    table: 'filter',
    params: {
      source: '2001:db8:85a3::8a2e:370:7334/128',
      destination: '2001:db8:85a3::8a2e:370:7334/128',
    },
  },
  'source_destination_ipv4_netmask' => {
    line: '-A INPUT -s 1.1.1.0/255.255.255.0 -d 2.2.0.0/255.255.0.0 -m comment --comment "000 source destination ipv4 netmask"',
    table: 'filter',
    params: {
      source: '1.1.1.0/24',
      destination: '2.2.0.0/16',
    },
  },
  'source_destination_ipv6_netmask' => {
    line: '-A INPUT -s 2001:db8:1234::/ffff:ffff:ffff:0000:0000:0000:0000:0000 -d 2001:db8:4321::/ffff:ffff:ffff:0000:0000:0000:0000:0000 -m comment --comment "000 source destination ipv6 netmask"',
    table: 'filter',
    params: {
      source: '2001:db8:1234::/48',
      destination: '2001:db8:4321::/48',
    },
  },
  'source_destination_negate_source' => {
    line: '-A INPUT ! -s 1.1.1.1 -d 2.2.2.2 -m comment --comment "000 negated source address"',
    table: 'filter',
    params: {
      source: '! 1.1.1.1/32',
      destination: '2.2.2.2/32',
    },
  },
  'source_destination_negate_destination' => {
    line: '-A INPUT -s 1.1.1.1 ! -d 2.2.2.2 -m comment --comment "000 negated destination address"',
    table: 'filter',
    params: {
      source: '1.1.1.1/32',
      destination: '! 2.2.2.2/32',
    },
  },
  'source_destination_negate_destination_alternative' => {
    line: '-A INPUT -s 1.1.1.1 -d ! 2.2.2.2 -m comment --comment "000 negated destination address alternative"',
    table: 'filter',
    params: {
      source: '1.1.1.1/32',
      destination: '! 2.2.2.2/32',
    },
  },
  'dport_range_1' => {
    line: '-A INPUT -m multiport --dports 1:1024 -m comment --comment "000 allow foo"',
    table: 'filter',
    params: {
      dport: ['1-1024'],
    },
  },
  'dport_range_2' => {
    line: '-A INPUT -m multiport --dports 15,512:1024 -m comment --comment "000 allow foo"',
    table: 'filter',
    params: {
      dport: ['15', '512-1024'],
    },
  },
  'sport_range_1' => {
    line: '-A INPUT -m multiport --sports 1:1024 -m comment --comment "000 allow foo"',
    table: 'filter',
    params: {
      sport: ['1-1024'],
    },
  },
  'sport_range_2' => {
    line: '-A INPUT -m multiport --sports 15,512:1024 -m comment --comment "000 allow foo"',
    table: 'filter',
    params: {
      sport: ['15', '512-1024'],
    },
  },
  'dst_type_1' => {
    line: '-A INPUT -m addrtype --dst-type LOCAL',
    table: 'filter',
    params: {
      dst_type: ['LOCAL'],
    },
  },
  'src_type_1' => {
    line: '-A INPUT -m addrtype --src-type LOCAL',
    table: 'filter',
    params: {
      src_type: ['LOCAL'],
    },
  },
  'dst_range_1' => {
    line: '-A INPUT -m iprange --dst-range 10.0.0.2-10.0.0.20',
    table: 'filter',
    params: {
      dst_range: '10.0.0.2-10.0.0.20',
    },
  },
  'src_range_1' => {
    line: '-A INPUT -m iprange --src-range 10.0.0.2-10.0.0.20',
    table: 'filter',
    params: {
      src_range: '10.0.0.2-10.0.0.20',
    },
  },
  'tcp_flags_1' => {
    line: '-A INPUT -p tcp -m tcp --tcp-flags SYN,RST,ACK,FIN SYN -m comment --comment "000 initiation"',
    table: 'filter',
    compare_all: true,
    chain: 'INPUT',
    proto: 'tcp',
    params: {
      chain: 'INPUT',
      ensure: :present,
      line: '-A INPUT -p tcp -m tcp --tcp-flags SYN,RST,ACK,FIN SYN -m comment --comment "000 initiation"',
      name: '000 initiation',
      proto: 'tcp',
      provider: 'iptables',
      table: 'filter',
      tcp_flags: 'SYN,RST,ACK,FIN SYN',
    },
  },
  'tcp_option_1' => {
    line: '-A INPUT -p tcp -m tcp --tcp-option 8 -m comment --comment "001 tcp_option works alone"',
    table: 'filter',
    chain: 'INPUT',
    proto: 'tcp',
    params: {
      chain: 'INPUT',
      ensure: :present,
      line: '-A INPUT -p tcp -m tcp --tcp-option 8 -m comment --comment "001 tcp_option works alone"',
      name: '001 tcp_option works alone',
      proto: 'tcp',
      provider: 'iptables',
      table: 'filter',
      tcp_option: '8',
    },
  },
  'tcp_option_2' => {
    line: '-A INPUT -p tcp -m tcp ! --tcp-option 8 -m comment --comment "002 tcp_option works alone, negated"',
    table: 'filter',
    chain: 'INPUT',
    proto: 'tcp',
    params: {
      chain: 'INPUT',
      ensure: :present,
      line: '-A INPUT -p tcp -m tcp ! --tcp-option 8 -m comment --comment "002 tcp_option works alone, negated"',
      name: '002 tcp_option works alone, negated',
      proto: 'tcp',
      provider: 'iptables',
      table: 'filter',
      tcp_option: '! 8',
    },
  },
  'tcp_option_with_tcp_flags_1' => {
    line: '-A INPUT -p tcp -m tcp --tcp-option 8 --tcp-flags FIN,SYN,RST,ACK SYN -m comment --comment "000 initiation"',
    table: 'filter',
    compare_all: true,
    chain: 'INPUT',
    proto: 'tcp',
    params: {
      chain: 'INPUT',
      ensure: :present,
      line: '-A INPUT -p tcp -m tcp --tcp-option 8 --tcp-flags FIN,SYN,RST,ACK SYN -m comment --comment "000 initiation"',
      name: '000 initiation',
      proto: 'tcp',
      provider: 'iptables',
      table: 'filter',
      tcp_flags: 'FIN,SYN,RST,ACK SYN',
      tcp_option: '8',
    },
  },
  'tcp_option_with_tcp_flags_2' => {
    line: '-A INPUT -p tcp -m tcp ! --tcp-option 8 --tcp-flags FIN,SYN,RST,ACK SYN -m comment --comment "000 initiation"',
    table: 'filter',
    compare_all: true,
    chain: 'INPUT',
    proto: 'tcp',
    params: {
      chain: 'INPUT',
      ensure: :present,
      line: '-A INPUT -p tcp -m tcp ! --tcp-option 8 --tcp-flags FIN,SYN,RST,ACK SYN -m comment --comment "000 initiation"',
      name: '000 initiation',
      proto: 'tcp',
      provider: 'iptables',
      table: 'filter',
      tcp_flags: 'FIN,SYN,RST,ACK SYN',
      tcp_option: '! 8',
    },
  },
  'state_returns_sorted_values' => {
    line: '-A INPUT -m state --state INVALID,RELATED,ESTABLISHED',
    table: 'filter',
    params: {
      state: ['ESTABLISHED', 'INVALID', 'RELATED'],
      jump: nil,
    },
  },
  'ctstate_returns_sorted_values' => {
    line: '-A INPUT -m conntrack --ctstate INVALID,RELATED,ESTABLISHED',
    table: 'filter',
    params: {
      ctstate: ['ESTABLISHED', 'INVALID', 'RELATED'],
      jump: nil,
    },
  },
  'comment_string_character_validation' => {
    line: '-A INPUT -s 192.168.0.1/32 -m comment --comment "000 allow from 192.168.0.1, please" -j ACCEPT',
    table: 'filter',
    params: {
      source: '192.168.0.1/32',
      jump: 'accept',
    },
  },
  'multiple_comments' => {
    line: '-A INPUT -s 192.168.0.1/32 -m comment --comment "000 allow from 192.168.0.1, please" -m comment --comment "another comment" -j ACCEPT',
    table: 'filter',
    params: {
      name: '000 allow from 192.168.0.1, please;another comment',
      jump: 'accept',
    },
  },
  'comments_without_quotes_with_underscores' => {
    line: '-A INPUT -s 192.168.0.1/32 -m comment --comment comment_without_quotes -j ACCEPT',
    table: 'filter',
    params: {
      name: '9000 comment_without_quotes',
      jump: 'accept',
    },
  },
  'comments_without_quotes_with_dashes' => {
    line: '-A INPUT -s 192.168.0.1/32 -m comment --comment 100-comment_without-quotes -j ACCEPT',
    table: 'filter',
    params: {
      name: '100-comment_without-quotes',
      jump: 'accept',
    },
  },
  'string_escape_sequences' => {
    line: '-A INPUT -m comment --comment "000 parse escaped \\"s, \\"s, \\\'s, \\\'s, \\\\s and \\\\s" -j ACCEPT',
    table: 'filter',
    params: {
      name: '000 parse escaped "s, "s, \'s, \'s, \\s and \\s',
      jump: 'accept',
    },
  },
  'log_level_debug' => {
    line: '-A INPUT -m state --state NEW -j LOG --log-level 7 -m comment --comment "956 INPUT log-level"',
    table: 'filter',
    params: {
      state: ['NEW'],
      log_level: '7',
      jump: 'LOG',
    },
  },
  'log_level_warn' => {
    line: '-A INPUT -m state --state NEW -j LOG -m comment --comment "956 INPUT log-level"',
    table: 'filter',
    params: {
      state: ['NEW'],
      log_level: '4',
      jump: 'LOG',
    },
  },
  'load_limit_module_and_implicit_burst' => {
    line: '-A INPUT -m multiport --dports 123 -m limit --limit 15/hour -m comment --comment "057 INPUT limit NTP"',
    table: 'filter',
    params: {
      dport: ['123'],
      limit: '15/hour',
      burst: '5',
    },
  },
  'limit_with_explicit_burst' => {
    line: '-A INPUT -m multiport --dports 123 -m limit --limit 30/hour --limit-burst 10 -m comment --comment "057 INPUT limit NTP"',
    table: 'filter',
    params: {
      dport: ['123'],
      limit: '30/hour',
      burst: '10',
    },
  },
  'proto_ipencap' => {
    line: '-A INPUT -p ipencap -m comment --comment "0100 INPUT accept ipencap"',
    table: 'filter',
    params: {
      proto: 'ipencap',
    },
  },
  'load_uid_owner_filter_module' => {
    line: '-A OUTPUT -m owner --uid-owner root -j ACCEPT -m comment --comment "057 OUTPUT uid root only"',
    table: 'filter',
    params: {
      jump: 'accept',
      uid: 'root',
      chain: 'OUTPUT',
    },
  },
  'load_uid_owner_postrouting_module' => {
    line: '-t mangle -A POSTROUTING -m owner --uid-owner root -j ACCEPT -m comment --comment "057 POSTROUTING uid root only"',
    table: 'mangle',
    params: {
      jump: 'accept',
      chain: 'POSTROUTING',
      uid: 'root',
    },
  },
  'load_gid_owner_filter_module' => {
    line: '-A OUTPUT -m owner --gid-owner root -j ACCEPT -m comment --comment "057 OUTPUT gid root only"',
    table: 'filter',
    params: {
      jump: 'accept',
      chain: 'OUTPUT',
      gid: 'root',
    },
  },
  'load_gid_owner_postrouting_module' => {
    line: '-t mangle -A POSTROUTING -m owner --gid-owner root -j ACCEPT -m comment --comment "057 POSTROUTING gid root only"',
    table: 'mangle',
    params: {
      jump: 'accept',
      chain: 'POSTROUTING',
      gid: 'root',
    },
  },
  'mark_set-mark' => {
    line: '-t mangle -A PREROUTING -j MARK --set-xmark 0x3e8/0xffffffff',
    table: 'mangle',
    params: {
      jump: 'MARK',
      chain: 'PREROUTING',
      set_mark: '0x3e8/0xffffffff',
    },
  },
  'iniface_1' => {
    line: '-A INPUT -i eth0 -j DROP -m comment --comment "060 iniface"',
    table: 'filter',
    params: {
      jump: 'drop',
      chain: 'INPUT',
      iniface: 'eth0',
    },
  },
  'ipset_negated' => {
    line: '-A PREROUTING -p tcp -m multiport --dports 1094 -m comment --comment "060 ipset" -m state --state NEW -m set ! --match-set setname1 src -j DROP',
    table: 'filter',
    params: {
      chain: 'PREROUTING',
      proto: 'tcp',
      dport: ['1094'],
      state: ['NEW'],
      ipset: ['! setname1 src'],
      jump: 'drop',
    },
  },
  'addrtype_limit_iface_out' => {
    line: '-A cali-POSTROUTING -o tunl0 -m comment --comment "000 cali:JHlpT-eSqR1TvyYm" -m addrtype --src-type LOCAL --limit-iface-out -j MASQUERADE',
    table: 'filter',
    params: {
      chain: 'cali-POSTROUTING',
      outiface: 'tunl0',
      name: '000 cali:JHlpT-eSqR1TvyYm',
      jump: 'MASQUERADE',
      src_type: ['LOCAL --limit-iface-out'],
    },
  },
  'addrtype_negated' => {
    line: '-A cali-POSTROUTING -o tunl0 -m comment --comment "000 cali:JHlpT-eSqR1TvyYm" -m addrtype ! --src-type LOCAL -j MASQUERADE',
    table: 'filter',
    params: {
      chain: 'cali-POSTROUTING',
      outiface: 'tunl0',
      name: '000 cali:JHlpT-eSqR1TvyYm',
      jump: 'MASQUERADE',
      src_type: ['! LOCAL'],
    },
  },
  'physdev_negated' => {
    line: '-A cali-POSTROUTING -o tunl0 -m comment --comment "010 cali:JHlpT-eSqR1TvyYm" -m physdev ! --physdev-is-in -j MASQUERADE',
    table: 'filter',
    params: {
      chain: 'cali-POSTROUTING',
      outiface: 'tunl0',
      name: '010 cali:JHlpT-eSqR1TvyYm',
      jump: 'MASQUERADE',
      physdev_is_in: '! ',
    },
  },
  'addrtype_multiple' => {
    line: '-A cali-POSTROUTING -o tunl0 -m comment --comment "000 cali:JHlpT-eSqR1TvyYm" -m addrtype ! --src-type LOCAL --limit-iface-out -m addrtype --src-type LOCAL -j MASQUERADE',
    table: 'filter',
    params: {
      chain: 'cali-POSTROUTING',
      outiface: 'tunl0',
      name: '000 cali:JHlpT-eSqR1TvyYm',
      jump: 'MASQUERADE',
      src_type: ['! LOCAL --limit-iface-out', 'LOCAL'],
    },
  },
  'u32' => {
    line: '-A cali-fw-cali08818b3e1e0 -m u32 --u32 "0x0>>0x16&0x3c@0xc>>0x8=0x1000"',
    table: 'filter',
    params: {
      chain: 'cali-fw-cali08818b3e1e0',
      name:  '9000 fff92a2f7e1c5e95f852fdd7e4bd103785db4ae08bc24edd8ed530403bc16e45',
    },
  },
  'iniface_1_negated' => {
    line: '-A INPUT ! -i eth0 -j DROP -m comment --comment "060 iniface"',
    table: 'filter',
    params: {
      jump: 'drop',
      chain: 'INPUT',
      iniface: '! eth0',
    },
  },
  'iniface_2_negated' => {
    line: '-A CHAIN-WITH-DASH ! -i eth0 -p tcp -m comment --comment "005 iniface 2" -j DROP',
    table: 'filter',
    params: {
      jump: 'drop',
      chain: 'CHAIN-WITH-DASH',
      iniface: '! eth0',
    },
  },
  'iniface_1_aliased' => {
    line: '-A INPUT -i eth0:1 -j DROP -m comment --comment "060 iniface"',
    table: 'filter',
    params: {
      jump: 'drop',
      chain: 'INPUT',
      iniface: 'eth0:1',
    },
  },
  'iniface_with_vlans_1' => {
    line: '-A INPUT -i eth0.234 -j DROP -m comment --comment "060 iniface"',
    table: 'filter',
    params: {
      jump: 'drop',
      chain: 'INPUT',
      iniface: 'eth0.234',
    },
  },
  'iniface_with_plus_1' => {
    line: '-A INPUT -i eth+ -j DROP -m comment --comment "060 iniface"',
    table: 'filter',
    params: {
      jump: 'drop',
      chain: 'INPUT',
      iniface: 'eth+',
    },
  },
  'outiface_1' => {
    line: '-A OUTPUT -o eth0 -j DROP -m comment --comment "060 outiface"',
    table: 'filter',
    params: {
      jump: 'drop',
      chain: 'OUTPUT',
      outiface: 'eth0',
    },
  },
  'outiface_1_negated' => {
    line: '-A OUTPUT ! -o eth0 -j DROP -m comment --comment "060 outiface"',
    table: 'filter',
    params: {
      jump: 'drop',
      chain: 'OUTPUT',
      outiface: '! eth0',
    },
  },
  'outiface_1_aliased' => {
    line: '-A OUTPUT -o eth0:2 -j DROP -m comment --comment "060 outiface"',
    table: 'filter',
    params: {
      jump: 'drop',
      chain: 'OUTPUT',
      outiface: 'eth0:2',
    },
  },
  'outiface_with_vlans_1' => {
    line: '-A OUTPUT -o eth0.234 -j DROP -m comment --comment "060 outiface"',
    table: 'filter',
    params: {
      jump: 'drop',
      chain: 'OUTPUT',
      outiface: 'eth0.234',
    },
  },
  'outiface_with_plus_1' => {
    line: '-A OUTPUT -o eth+ -j DROP -m comment --comment "060 outiface"',
    table: 'filter',
    params: {
      jump: 'drop',
      chain: 'OUTPUT',
      outiface: 'eth+',
    },
  },
  'pkttype multicast' => {
    line: '-A INPUT -m pkttype --pkt-type multicast -j ACCEPT',
    table: 'filter',
    params: {
      jump: 'accept',
      pkttype: 'multicast',
    },
  },
  'socket_option' => {
    line: '-A PREROUTING -m socket -j ACCEPT',
    table: 'mangle',
    params: {
      jump: 'accept',
      chain: 'PREROUTING',
      socket: true,
    },
  },
  'isfragment_option' => {
    line: '-A INPUT -f -j ACCEPT -m comment --comment "010 a-f comment with dashf"',
    table: 'filter',
    params: {
      name: '010 a-f comment with dashf',
      jump: 'accept',
      isfragment: true,
    },
  },
  'single_tcp_sport' => {
    line: '-A OUTPUT -s 10.94.100.46/32 -p tcp -m tcp --sport 20443 -j ACCEPT',
    table: 'mangle',
    params: {
      jump: 'accept',
      chain: 'OUTPUT',
      source: '10.94.100.46/32',
      proto: 'tcp',
      sport: ['20443'],
    },
  },
  'single_udp_sport' => {
    line: '-A OUTPUT -s 10.94.100.46/32 -p udp -m udp --sport 20443 -j ACCEPT',
    table: 'mangle',
    params: {
      jump: 'accept',
      chain: 'OUTPUT',
      source: '10.94.100.46/32',
      proto: 'udp',
      sport: ['20443'],
    },
  },
  'single_tcp_dport' => {
    line: '-A OUTPUT -s 10.94.100.46/32 -p tcp -m tcp --dport 20443 -j ACCEPT',
    table: 'mangle',
    params: {
      jump: 'accept',
      chain: 'OUTPUT',
      source: '10.94.100.46/32',
      proto: 'tcp',
      dport: ['20443'],
    },
  },
  'single_udp_dport' => {
    line: '-A OUTPUT -s 10.94.100.46/32 -p udp -m udp --dport 20443 -j ACCEPT',
    table: 'mangle',
    params: {
      jump: 'accept',
      chain: 'OUTPUT',
      source: '10.94.100.46/32',
      proto: 'udp',
      dport: ['20443'],
    },
  },
  'connlimit_above' => {
    line: '-A INPUT -p tcp -m multiport --dports 22 -m connlimit --connlimit-above 10 --connlimit-mask 32 -j REJECT --reject-with icmp-port-unreachable -m comment --comment "061 REJECT connlimit_above 10"', # rubocop:disable Layout/LineLength
    table: 'filter',
    params: {
      proto: 'tcp',
      dport: ['22'],
      connlimit_above: '10',
      jump: 'reject',
    },
  },
  'connlimit_above_with_connlimit_mask' => {
    line: '-A INPUT -p tcp -m multiport --dports 22 -m connlimit --connlimit-above 10 --connlimit-mask 24 -j REJECT --reject-with icmp-port-unreachable -m comment --comment "061 REJECT connlimit_above 10 with mask 24"', # rubocop:disable Layout/LineLength,
    table: 'filter',
    params: {
      proto: 'tcp',
      dport: ['22'],
      connlimit_above: '10',
      connlimit_mask: '24',
      jump: 'reject',
    },
  },
  'connmark' => {
    line: '-A INPUT -m connmark --mark 0x1 -j REJECT --reject-with icmp-port-unreachable -m comment --comment "062 REJECT connmark"',
    table: 'filter',
    params: {
      proto: 'all',
      connmark: '0x1',
      jump: 'reject',
    },
  },
  'disallow_esp_protocol' => {
    line: '-t filter ! -p esp -j ACCEPT -m comment --comment "063 disallow esp protocol"',
    table: 'filter',
    params: {
      name: '063 disallow esp protocol',
      jump: 'accept',
      proto: '! esp',
    },
  },
  'drop_new_packets_without_syn' => {
    line: '-t filter ! -s 10.0.0.0/8 ! -p tcp -m tcp ! --tcp-flags FIN,SYN,RST,ACK SYN -m state --state NEW -j DROP -m comment --comment "064 drop NEW non-tcp external packets with FIN/RST/ACK set and SYN unset"', # rubocop:disable Layout/LineLength
    table: 'filter',
    params: {
      name: '064 drop NEW non-tcp external packets with FIN/RST/ACK set and SYN unset',
      state: ['NEW'],
      jump: 'drop',
      proto: '! tcp',
      source: '! 10.0.0.0/8',
      tcp_flags: '! FIN,SYN,RST,ACK SYN',
    },
  },
  'negate_dport_and_sport' => {
    line: '-A nova-compute-FORWARD -s 0.0.0.0/32 -d 255.255.255.255/32 -p udp -m udp ! --sport 68,69 ! --dport 67,66 -j ACCEPT',
    table: 'filter',
    params: {
      jump: 'accept',
      chain: 'nova-compute-FORWARD',
      source: '0.0.0.0/32',
      destination: '255.255.255.255/32',
      sport: ['! 68', '! 69'],
      dport: ['! 67', '! 66'],
      proto: 'udp',
    },
  },
  'match_mark' => {
    line: '-A INPUT -p tcp -m mark --mark 0x1 -m connlimit --connlimit-above 10 --connlimit-mask 32 -j REJECT --reject-with icmp-port-unreachable -m comment --comment "066 REJECT connlimit_above 10 with mask 32 and mark matches"', # rubocop:disable Layout/LineLength
    table: 'filter',
    params: {
      proto: 'tcp',
      connlimit_above: '10',
      connlimit_mask: '32',
      match_mark: '0x1',
      jump: 'reject',
    },
  },
  'clamp_mss_to_pmtu' => {
    line: '-A INPUT -p tcp -m tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu -m comment --comment "067 change max segment size"',
    table: 'filter',
    params: {
      name: '067 change max segment size',
      table: 'filter',
      proto: 'tcp',
      tcp_flags: 'SYN,RST SYN',
      jump: 'TCPMSS',
      clamp_mss_to_pmtu: true,
    },
  },
  'mangled_chain_name_with_-f' => {
    line: '-A foo-filter -p tcp -j ACCEPT -m comment --comment "068 chain name containing -f"',
    params: {
      name: '068 chain name containing -f',
      jump: 'accept',
      chain: 'foo-filter',
    },
  },
  'length_1' => {
    line: '-A INPUT -m length --length 42000',
    table: 'filter',
    params: {
      length: '42000',
    },
  },
  'length_2' => {
    line: '-A INPUT -m length --length 1492:65535',
    table: 'filter',
    params: {
      length: '1492-65535',
    },
  },
  'string_matching_1' => {
    line: '-A INPUT -m string --string "GET /index.html"',
    table: 'filter',
    params: {
      string: 'GET /index.html',
    },
  },
  'string_matching_2' => {
    line: '-A INPUT -m string --string "GET /index.html" --algo bm',
    table: 'filter',
    params: {
      string: 'GET /index.html',
      string_algo: 'bm',
    },
  },
  'string_matching_3' => {
    line: '-A INPUT -m string --string "GET /index.html" --from 1',
    table: 'filter',
    params: {
      string: 'GET /index.html',
      string_from: '1',
    },
  },
  'hexstring_matching_1' => {
    line: '-A INPUT -m string --hex-string "|0000FF0001|" --algo bm',
    table: 'filter',
    params: {
      string_hex: '|0000FF0001|',
      string_algo: 'bm',
    },
  },
  'nfqueue_jump1' => {
    line: '-A INPUT -m tcp -p tcp -s 1.2.3.4/32 -d 4.3.2.1/32 -j NFQUEUE --queue-num 50 -m comment --comment "000 nfqueue specify queue_num"',
    table: 'filter',
    params: {
      name: '000 nfqueue specify queue_num',
      source: '1.2.3.4/32',
      destination: '4.3.2.1/32',
      jump: 'NFQUEUE',
      queue_num: '50',
      proto: 'tcp',
    },
  },
  'nfqueue_jump2' => {
    line: '-A INPUT -m tcp -p tcp -s 1.2.3.4/32 -d 4.3.2.1/32 -j NFQUEUE --queue-num 50 --queue-bypass -m comment --comment "002 nfqueue specify queue_num and queue_bypass"',
    table: 'filter',
    params: {
      name: '002 nfqueue specify queue_num and queue_bypass',
      source: '1.2.3.4/32',
      destination: '4.3.2.1/32',
      jump: 'NFQUEUE',
      queue_num: '50',
      queue_bypass: true,
      proto: 'tcp',
    },
  },
  'nfqueue_jump3' => {
    line: '-A INPUT -m tcp -p tcp -s 1.2.3.4/32 -d 4.3.2.1/32 -j NFQUEUE -m comment --comment "003 nfqueue dont specify queue_num or queue_bypass"',
    table: 'filter',
    params: {
      name: '003 nfqueue dont specify queue_num or queue_bypass',
      source: '1.2.3.4/32',
      destination: '4.3.2.1/32',
      jump: 'NFQUEUE',
      proto: 'tcp',
    },
  },
  'parser_sanity_check' => {
    line: '-A INPUT -s 1.2.3.4/32 -p tcp -m tcp --dport 80 --tcp-flags FIN,SYN,RST,ACK SYN -m comment --comment "004 parser sanity check" -j ACCEPT',
    table: 'filter',
    produce_warning: true,
    params: {},
  },
  'cgroup_matching_1' => {
    line: '-A INPUT -m cgroup --cgroup "0x100001"',
    table: 'filter',
    params: {
      cgroup: '0x100001',
    },
  },
  'notrack' => {
    line: '-A PREROUTING -p udp -m multiport --dports 53 -m comment --comment "004 do not track UDP connections to port 53" -j CT --notrack',
    table: 'raw',
    params: {
      chain: 'PREROUTING',
      proto: 'udp',
      dport: ['53'],
      jump: 'CT',
      notrack: true
    }
  },
}.freeze

# This hash is for testing converting a hash to an argument line.
HASH_TO_ARGS = {
  'long_rule_1' => {
    params: {
      jump: 'accept',
      chain: 'INPUT',
      destination: '1.1.1.1',
      dport: ['7061', '7062'],
      ensure: :present,
      name: '000 allow foo',
      proto: 'tcp',
      source: '1.1.1.1',
      sport: ['7061', '7062'],
      table: 'filter',
    },
    args: ['-t', :filter, '-s', '1.1.1.1/32', '-d', '1.1.1.1/32', '-p', :tcp, '-m', 'multiport', '--sports', '7061,7062', '-m', 'multiport', '--dports', '7061,7062', '-j', 'ACCEPT', '-m', 'comment', '--comment', '000 allow foo'], # rubocop:disable Layout/LineLength
  },
  'long_rule_2' => {
    params: {
      chain: 'INPUT',
      destination: '2.10.13.3/24',
      dport: ['7061'],
      ensure: :present,
      jump: 'my_custom_chain',
      name: '700 allow bar',
      proto: 'udp',
      source: '1.1.1.1',
      sport: ['7061', '7062'],
      table: 'filter',
    },
    args: ['-t', :filter, '-s', '1.1.1.1/32', '-d', '2.10.13.0/24', '-p', :udp, '-m', 'multiport', '--sports', '7061,7062', '-m', 'multiport', '--dports', '7061', '-j', 'my_custom_chain', '-m', 'comment', '--comment', '700 allow bar'], # rubocop:disable Layout/LineLength
  },
  'no_action' => {
    params: {
      name: '100 no action',
      table: 'filter',
    },
    args: ['-t', :filter, '-p', :tcp, '-m', 'comment', '--comment',
           '100 no action'],
  },
  'zero_prefixlen_ipv4' => {
    params: {
      name: '100 zero prefix length ipv4',
      table: 'filter',
      source: '0.0.0.0/0',
      destination: '0.0.0.0/0',
    },
    args: ['-t', :filter, '-p', :tcp, '-m', 'comment', '--comment', '100 zero prefix length ipv4'],
  },
  'zero_prefixlen_ipv6' => {
    params: {
      name: '100 zero prefix length ipv6',
      table: 'filter',
      source: '::/0',
      destination: '::/0',
    },
    args: ['-t', :filter, '-p', :tcp, '-m', 'comment', '--comment', '100 zero prefix length ipv6'],
  },
  'source_destination_ipv4_no_cidr' => {
    params: {
      name: '000 source destination ipv4 no cidr',
      table: 'filter',
      source: '1.1.1.1',
      destination: '2.2.2.2',
    },
    args: ['-t', :filter, '-s', '1.1.1.1/32', '-d', '2.2.2.2/32', '-p', :tcp, '-m', 'comment', '--comment', '000 source destination ipv4 no cidr'],
  },
  'source_destination_ipv6_no_cidr' => {
    params: {
      name: '000 source destination ipv6 no cidr',
      table: 'filter',
      source: '2001:db8:1234::',
      destination: '2001:db8:4321::',
    },
    args: ['-t', :filter, '-s', '2001:db8:1234::/128', '-d', '2001:db8:4321::/128', '-p', :tcp, '-m', 'comment', '--comment', '000 source destination ipv6 no cidr'],
  },
  'source_destination_ipv4_netmask' => {
    params: {
      name: '000 source destination ipv4 netmask',
      table: 'filter',
      source: '1.1.1.0/255.255.255.0',
      destination: '2.2.0.0/255.255.0.0',
    },
    args: ['-t', :filter, '-s', '1.1.1.0/24', '-d', '2.2.0.0/16', '-p', :tcp, '-m', 'comment', '--comment', '000 source destination ipv4 netmask'],
  },
  'source_destination_ipv6_netmask' => {
    params: {
      name: '000 source destination ipv6 netmask',
      table: 'filter',
      source: '2001:db8:1234::/ffff:ffff:ffff:0000:0000:0000:0000:0000',
      destination: '2001:db8:4321::/ffff:ffff:ffff:0000:0000:0000:0000:0000',
    },
    args: ['-t', :filter, '-s', '2001:db8:1234::/48', '-d', '2001:db8:4321::/48', '-p', :tcp, '-m', 'comment', '--comment', '000 source destination ipv6 netmask'],
  },
  'sport_range_1' => {
    params: {
      name: '100 sport range',
      sport: ['1-1024'],
      table: 'filter',
    },
    args: ['-t', :filter, '-p', :tcp, '-m', 'multiport', '--sports', '1:1024', '-m', 'comment', '--comment', '100 sport range'],
  },
  'sport_range_2' => {
    params: {
      name: '100 sport range',
      sport: ['15', '512-1024'],
      table: 'filter',
    },
    args: ['-t', :filter, '-p', :tcp, '-m', 'multiport', '--sports', '15,512:1024', '-m', 'comment', '--comment', '100 sport range'],
  },
  'dport_range_1' => {
    params: {
      name: '100 sport range',
      dport: ['1-1024'],
      table: 'filter',
    },
    args: ['-t', :filter, '-p', :tcp, '-m', 'multiport', '--dports', '1:1024', '-m', 'comment', '--comment', '100 sport range'],
  },
  'dport_range_2' => {
    params: {
      name: '100 sport range',
      dport: ['15', '512-1024'],
      table: 'filter',
    },
    args: ['-t', :filter, '-p', :tcp, '-m', 'multiport', '--dports', '15,512:1024', '-m', 'comment', '--comment', '100 sport range'],
  },
  'dst_type_1' => {
    params: {
      name: '000 dst_type',
      table: 'filter',
      dst_type: 'LOCAL',
    },
    args: ['-t', :filter, '-p', :tcp, '-m', 'addrtype', '--dst-type', 'LOCAL', '-m', 'comment', '--comment', '000 dst_type'],
  },
  'dst_type_as_array' => {
    params: {
      name: '000 dst_type',
      table: 'filter',
      dst_type: ['LOCAL'],
    },
    args: ['-t', :filter, '-p', :tcp, '-m', 'addrtype', '--dst-type', 'LOCAL', '-m', 'comment', '--comment', '000 dst_type'],
  },
  'dst_type_multiple' => {
    params: {
      name: '000 dst_type',
      table: 'filter',
      dst_type: ['LOCAL', '! LOCAL'],
    },
    args: ['-t', :filter, '-p', :tcp, '-m', 'addrtype', '--dst-type', 'LOCAL', '-m', 'addrtype', '!', '--dst-type', 'LOCAL', '-m', 'comment', '--comment', '000 dst_type'],
  },
  'dst_type_limit' => {
    params: {
      name: '000 dst_type',
      table: 'filter',
      dst_type: ['LOCAL --limit-iface-in'],
    },
    args: ['-t', :filter, '-p', :tcp, '-m', 'addrtype', '--dst-type', 'LOCAL', '--limit-iface-in', '-m', 'comment', '--comment', '000 dst_type'],
  },
  'src_type_1' => {
    params: {
      name: '000 src_type',
      table: 'filter',
      src_type: 'LOCAL',
    },
    args: ['-t', :filter, '-p', :tcp, '-m', 'addrtype', '--src-type', 'LOCAL', '-m', 'comment', '--comment', '000 src_type'],
  },
  'src_type_as_array' => {
    params: {
      name: '000 src_type',
      table: 'filter',
      src_type: ['LOCAL'],
    },
    args: ['-t', :filter, '-p', :tcp, '-m', 'addrtype', '--src-type', 'LOCAL', '-m', 'comment', '--comment', '000 src_type'],
  },
  'src_type_multiple' => {
    params: {
      name: '000 src_type',
      table: 'filter',
      src_type: ['LOCAL', '! LOCAL'],
    },
    args: ['-t', :filter, '-p', :tcp, '-m', 'addrtype', '--src-type', 'LOCAL', '-m', 'addrtype', '!', '--src-type', 'LOCAL', '-m', 'comment', '--comment', '000 src_type'],
  },
  'dst_range_1' => {
    params: {
      name: '000 dst_range',
      table: 'filter',
      dst_range: '10.0.0.1-10.0.0.10',
    },
    args: ['-t', :filter, '-p', :tcp, '-m', 'iprange', '--dst-range', '10.0.0.1-10.0.0.10', '-m', 'comment', '--comment', '000 dst_range'],
  },
  'src_range_1' => {
    params: {
      name: '000 src_range',
      table: 'filter',
      dst_range: '10.0.0.1-10.0.0.10',
    },
    args: ['-t', :filter, '-p', :tcp, '-m', 'iprange', '--dst-range', '10.0.0.1-10.0.0.10', '-m', 'comment', '--comment', '000 src_range'],
  },
  'tcp_flags_1' => {
    params: {
      name: '000 initiation',
      tcp_flags: 'SYN,RST,ACK,FIN SYN',
      table: 'filter',
    },

    args: ['-t', :filter, '-p', :tcp, '-m', 'tcp', '--tcp-flags', 'SYN,RST,ACK,FIN', 'SYN', '-m', 'comment', '--comment', '000 initiation'],
  },
  'tcp_option_1' => {
    params: {
      name: '000 initiation',
      table: 'filter',
      chain: 'INPUT',
      proto: 'tcp',
      tcp_option: '8',
    },
    args: ['-t', :filter, '-p', :tcp, '-m', 'tcp', '--tcp-option', '8', '-m', 'comment', '--comment', '000 initiation'],
  },
  'tcp_option_2' => {
    params: {
      name: '000 initiation',
      table: 'filter',
      chain: 'INPUT',
      proto: 'tcp',
      tcp_option: '! 8',
    },
    args: ['-t', :filter, '-p', :tcp, '-m', 'tcp', '!', '--tcp-option', '8', '-m', 'comment', '--comment', '000 initiation'],
  },
  'tcp_option_with_tcp_flags_1' => {
    params: {
      name: '000 initiation',
      table: 'filter',
      chain: 'INPUT',
      proto: 'tcp',
      tcp_flags: 'FIN,SYN,RST,ACK SYN',
      tcp_option: '8',
    },
    args: ['-t', :filter, '-p', :tcp, '-m', 'tcp', '--tcp-option', '8', '--tcp-flags', 'FIN,SYN,RST,ACK', 'SYN', '-m', 'comment', '--comment', '000 initiation'],
  },
  'tcp_option_with_tcp_flags_2' => {
    params: {
      name: '000 initiation',
      table: 'filter',
      chain: 'INPUT',
      proto: 'tcp',
      tcp_flags: 'FIN,SYN,RST,ACK SYN',
      tcp_option: '! 8',
    },
    args: ['-t', :filter, '-p', :tcp, '-m', 'tcp', '!', '--tcp-option', '8', '--tcp-flags', 'FIN,SYN,RST,ACK', 'SYN', '-m', 'comment', '--comment', '000 initiation'],
  },
  'states_set_from_array' => {
    params: {
      name: '100 states_set_from_array',
      table: 'filter',
      state: ['ESTABLISHED', 'INVALID'],
    },
    args: ['-t', :filter, '-p', :tcp, '-m', 'state', '--state', 'ESTABLISHED,INVALID', '-m', 'comment', '--comment', '100 states_set_from_array'],
  },
  'ctstates_set_from_array' => {
    params: {
      name: '100 ctstates_set_from_array',
      table: 'filter',
      ctstate: ['ESTABLISHED', 'INVALID'],
    },
    args: ['-t', :filter, '-p', :tcp, '-m', 'conntrack', '--ctstate', 'ESTABLISHED,INVALID', '-m', 'comment', '--comment', '100 ctstates_set_from_array'],
  },
  'comment_string_character_validation' => {
    params: {
      name: '000 allow from 192.168.0.1, please',
      table: 'filter',
      source: '192.168.0.1',
    },
    args: ['-t', :filter, '-s', '192.168.0.1/32', '-p', :tcp, '-m', 'comment', '--comment', '000 allow from 192.168.0.1, please'],
  },
  'comment_string_character_validation_2' => {
    params: {
      name: '000 allow symbols ( $+<=>^`|~ ) in ruby >= 1.9',
      table: 'filter',
    },
    args: ['-t', :filter, '-p', :tcp, '-m', 'comment', '--comment', '000 allow symbols ( $+<=>^`|~ ) in ruby >= 1.9'],
  },
  'log_level_debug' => {
    params: {
      name: '956 INPUT log-level',
      table: 'filter',
      state: 'NEW',
      jump: 'LOG',
      log_level: 'debug',
    },
    args: ['-t', :filter, '-p', :tcp, '-m', 'state', '--state', 'NEW', '-j', 'LOG', '--log-level', '7', '-m', 'comment', '--comment', '956 INPUT log-level'],
  },
  'log_level_warn' => {
    params: {
      name: '956 INPUT log-level',
      table: 'filter',
      state: 'NEW',
      jump: 'LOG',
      log_level: 'warn',
    },
    args: ['-t', :filter, '-p', :tcp, '-m', 'state', '--state', 'NEW', '-j', 'LOG', '--log-level', '4', '-m', 'comment', '--comment', '956 INPUT log-level'],
  },
  'load_limit_module_and_implicit_burst' => {
    params: {
      name: '057 INPUT limit NTP',
      table: 'filter',
      dport: '123',
      limit: '15/hour',
    },
    args: ['-t', :filter, '-p', :tcp, '-m', 'multiport', '--dports', '123', '-m', 'limit', '--limit', '15/hour', '-m', 'comment', '--comment', '057 INPUT limit NTP'],
  },
  'limit_with_explicit_burst' => {
    params: {
      name: '057 INPUT limit NTP',
      table: 'filter',
      dport: '123',
      limit: '30/hour',
      burst: '10',
    },
    args: ['-t', :filter, '-p', :tcp, '-m', 'multiport', '--dports', '123', '-m', 'limit', '--limit', '30/hour', '--limit-burst', '10', '-m', 'comment', '--comment', '057 INPUT limit NTP'],
  },
  'proto_ipencap' => {
    params: {
      name: '0100 INPUT accept ipencap',
      table: 'filter',
      proto: 'ipencap',
    },
    args: ['-t', :filter, '-p', :ipencap, '-m', 'comment', '--comment', '0100 INPUT accept ipencap'],
  },
  'load_uid_owner_filter_module' => {
    params: {
      name: '057 OUTPUT uid root only',
      table: 'filter',
      uid: 'root',
      jump: 'accept',
      chain: 'OUTPUT',
      proto: 'all',
    },
    args: ['-t', :filter, '-p', :all, '-m', 'owner', '--uid-owner', 'root', '-j', 'ACCEPT', '-m', 'comment', '--comment', '057 OUTPUT uid root only'],
  },
  'load_uid_owner_postrouting_module' => {
    params: {
      name: '057 POSTROUTING uid root only',
      table: 'mangle',
      uid: 'root',
      jump: 'accept',
      chain: 'POSTROUTING',
      proto: 'all',
    },
    args: ['-t', :mangle, '-p', :all, '-m', 'owner', '--uid-owner', 'root', '-j', 'ACCEPT', '-m', 'comment', '--comment', '057 POSTROUTING uid root only'],
  },
  'load_gid_owner_filter_module' => {
    params: {
      name: '057 OUTPUT gid root only',
      table: 'filter',
      chain: 'OUTPUT',
      gid: 'root',
      jump: 'accept',
      proto: 'all',
    },
    args: ['-t', :filter, '-p', :all, '-m', 'owner', '--gid-owner', 'root', '-j', 'ACCEPT', '-m', 'comment', '--comment', '057 OUTPUT gid root only'],
  },
  'load_gid_owner_postrouting_module' => {
    params: {
      name: '057 POSTROUTING gid root only',
      table: 'mangle',
      gid: 'root',
      jump: 'accept',
      chain: 'POSTROUTING',
      proto: 'all',
    },
    args: ['-t', :mangle, '-p', :all, '-m', 'owner', '--gid-owner', 'root', '-j', 'ACCEPT', '-m', 'comment', '--comment', '057 POSTROUTING gid root only'],
  },
  'mark_set-mark_int' => {
    params: {
      name: '058 set-mark 1000',
      table: 'mangle',
      jump: 'MARK',
      chain: 'PREROUTING',
      set_mark: '1000',
    },
    args: ['-t', :mangle, '-p', :tcp, '-j', 'MARK', '--set-xmark', '0x3e8/0xffffffff', '-m', 'comment', '--comment', '058 set-mark 1000'],
  },
  'mark_set-mark_hex' => {
    params: {
      name: '058 set-mark 0x32',
      table: 'mangle',
      jump: 'MARK',
      chain: 'PREROUTING',
      set_mark: '0x32',
    },
    args: ['-t', :mangle, '-p', :tcp, '-j', 'MARK', '--set-xmark', '0x32/0xffffffff', '-m', 'comment', '--comment', '058 set-mark 0x32'],
  },
  'mark_set-mark_hex_with_hex_mask' => {
    params: {
      name: '058 set-mark 0x32/0xffffffff',
      table: 'mangle',
      jump: 'MARK',
      chain: 'PREROUTING',
      set_mark: '0x32/0xffffffff',
    },
    args: ['-t', :mangle, '-p', :tcp, '-j', 'MARK', '--set-xmark', '0x32/0xffffffff', '-m', 'comment', '--comment', '058 set-mark 0x32/0xffffffff'],
  },
  'mark_set-mark_hex_with_mask' => {
    params: {
      name: '058 set-mark 0x32/4',
      table: 'mangle',
      jump: 'MARK',
      chain: 'PREROUTING',
      set_mark: '0x32/4',
    },
    args: ['-t', :mangle, '-p', :tcp, '-j', 'MARK', '--set-xmark', '0x32/0x4', '-m', 'comment', '--comment', '058 set-mark 0x32/4'],
  },
  'iniface_1' => {
    params: {
      name: '060 iniface',
      table: 'filter',
      jump: 'drop',
      chain: 'INPUT',
      iniface: 'eth0',
    },
    args: ['-t', :filter, '-i', 'eth0', '-p', :tcp, '-j', 'DROP', '-m', 'comment', '--comment', '060 iniface'],
  },
  'iniface_with_vlans_1' => {
    params: {
      name: '060 iniface',
      table: 'filter',
      jump: 'drop',
      chain: 'INPUT',
      iniface: 'eth0.234',
    },
    args: ['-t', :filter, '-i', 'eth0.234', '-p', :tcp, '-j', 'DROP', '-m', 'comment', '--comment', '060 iniface'],
  },
  'iniface_with_plus_1' => {
    params: {
      name: '060 iniface',
      table: 'filter',
      jump: 'drop',
      chain: 'INPUT',
      iniface: 'eth+',
    },
    args: ['-t', :filter, '-i', 'eth+', '-p', :tcp, '-j', 'DROP', '-m', 'comment', '--comment', '060 iniface'],
  },
  'outiface_1' => {
    params: {
      name: '060 outiface',
      table: 'filter',
      jump: 'drop',
      chain: 'OUTPUT',
      outiface: 'eth0',
    },
    args: ['-t', :filter, '-o', 'eth0', '-p', :tcp, '-j', 'DROP', '-m', 'comment', '--comment', '060 outiface'],
  },
  'outiface_with_vlans_1' => {
    params: {
      name: '060 outiface',
      table: 'filter',
      jump: 'drop',
      chain: 'OUTPUT',
      outiface: 'eth0.234',
    },
    args: ['-t', :filter, '-o', 'eth0.234', '-p', :tcp, '-j', 'DROP', '-m', 'comment', '--comment', '060 outiface'],
  },
  'outiface_with_plus_1' => {
    params: {
      name: '060 outiface',
      table: 'filter',
      jump: 'drop',
      chain: 'OUTPUT',
      outiface: 'eth+',
    },
    args: ['-t', :filter, '-o', 'eth+', '-p', :tcp, '-j', 'DROP', '-m', 'comment', '--comment', '060 outiface'],
  },
  'pkttype multicast' => {
    params: {
      name: '062 pkttype multicast',
      table: 'filter',
      jump: 'accept',
      chain: 'INPUT',
      iniface: 'eth0',
      pkttype: 'multicast',
    },
    args: ['-t', :filter, '-i', 'eth0', '-p', :tcp, '-m', 'pkttype', '--pkt-type', :multicast, '-j', 'ACCEPT', '-m', 'comment', '--comment', '062 pkttype multicast'],
  },
  'socket_option' => {
    params: {
      name: '050 socket option',
      table: 'mangle',
      jump: 'accept',
      chain: 'PREROUTING',
      socket: true,
    },
    args: ['-t', :mangle, '-p', :tcp, '-m', 'socket', '-j', 'ACCEPT', '-m', 'comment', '--comment', '050 socket option'],
  },
  'isfragment_option' => {
    params: {
      name: '050 isfragment option',
      table: 'filter',
      proto: :all,
      jump: 'accept',
      isfragment: true,
    },
    args: ['-t', :filter, '-p', :all, '-f', '-j', 'ACCEPT', '-m', 'comment', '--comment', '050 isfragment option'],
  },
  'isfragment_option not changing -f in comment' => {
    params: {
      name: '050 testcomment-with-fdashf',
      table: 'filter',
      proto: :all,
      jump: 'accept',
    },
    args: ['-t', :filter, '-p', :all, '-j', 'ACCEPT', '-m', 'comment', '--comment', '050 testcomment-with-fdashf'],
  },
  'connlimit_above' => {
    params: {
      name: '061 REJECT connlimit_above 10',
      table: 'filter',
      proto: 'tcp',
      dport: ['22'],
      connlimit_above: '10',
      jump: 'reject',
    },
    args: ['-t', :filter, '-p', :tcp, '-m', 'multiport', '--dports', '22', '-j', 'REJECT', '-m', 'connlimit', '--connlimit-above', '10', '-m', 'comment', '--comment', '061 REJECT connlimit_above 10'],
  },
  'connlimit_above_with_connlimit_mask' => {
    params: {
      name: '061 REJECT connlimit_above 10 with mask 24',
      table: 'filter',
      proto: 'tcp',
      dport: ['22'],
      connlimit_above: '10',
      connlimit_mask: '24',
      jump: 'reject',
    },
    args: ['-t', :filter, '-p', :tcp, '-m', 'multiport', '--dports', '22', '-j', 'REJECT', '-m', 'connlimit', '--connlimit-above', '10', '--connlimit-mask', '24', '-m', 'comment', '--comment', '061 REJECT connlimit_above 10 with mask 24'], # rubocop:disable Layout/LineLength
  },
  'connmark' => {
    params: {
      name: '062 REJECT connmark',
      table: 'filter',
      proto: 'all',
      connmark: '0x1',
      jump: 'reject',
    },
    args: ['-t', :filter, '-p', :all, '-j', 'REJECT', '-m', 'connmark', '--mark', '0x1', '-m', 'comment', '--comment', '062 REJECT connmark'],
  },
  'disallow_esp_protocol' => {
    params: {
      name: '063 disallow esp protocol',
      table: 'filter',
      jump: 'accept',
      proto: '! esp',
    },
    args: ['-t', :filter, '!', '-p', :esp, '-j', 'ACCEPT', '-m', 'comment', '--comment', '063 disallow esp protocol'],
  },
  'drop_new_packets_without_syn' => {
    params: {
      name: '064 drop NEW non-tcp external packets with FIN/RST/ACK set and SYN unset',
      table: 'filter',
      chain: 'INPUT',
      state: ['NEW'],
      jump: 'drop',
      proto: '! tcp',
      source: '! 10.0.0.0/8',
      tcp_flags: '! FIN,SYN,RST,ACK SYN',
    },
    args: ['-t', :filter, '!', '-s', '10.0.0.0/8', '!', '-p', :tcp, '-m', 'tcp', '!', '--tcp-flags', 'FIN,SYN,RST,ACK', 'SYN', '-m', 'state', '--state', 'NEW', '-j', 'DROP', '-m', 'comment', '--comment', '064 drop NEW non-tcp external packets with FIN/RST/ACK set and SYN unset'], # rubocop:disable Layout/LineLength
  },
  'negate_dport_and_sport' => {
    params: {
      name: '065 negate dport and sport',
      table: 'filter',
      jump: 'accept',
      chain: 'nova-compute-FORWARD',
      source: '0.0.0.0/32',
      destination: '255.255.255.255/32',
      sport: ['! 68', '! 69'],
      dport: ['! 67', '! 66'],
      proto: 'udp',
    },
    args: ['-t', :filter, '-s', '0.0.0.0/32', '-d', '255.255.255.255/32', '-p', :udp, '-m', 'multiport', '!', '--sports', '68,69', '-m', 'multiport', '!', '--dports', '67,66', '-j', 'ACCEPT', '-m', 'comment', '--comment', '065 negate dport and sport'], # rubocop:disable Layout/LineLength
  },
  'match_mark' => {
    params: {
      name: '066 REJECT connlimit_above 10 with mask 32 and mark matches',
      table: 'filter',
      proto: 'tcp',
      connlimit_above: '10',
      connlimit_mask: '32',
      match_mark: '0x1',
      jump: 'reject',
    },
    args: ['-t', :filter, '-p', :tcp, '-j', 'REJECT', '-m', 'mark', '--mark', '0x1', '-m', 'connlimit', '--connlimit-above', '10', '--connlimit-mask', '32', '-m', 'comment', '--comment', '066 REJECT connlimit_above 10 with mask 32 and mark matches'], # rubocop:disable Layout/LineLength
  },
  'clamp_mss_to_pmtu' => {
    params: {
      name: '067 change max segment size',
      table: 'filter',
      proto: 'tcp',
      tcp_flags: 'SYN,RST SYN',
      jump: 'TCPMSS',
      clamp_mss_to_pmtu: true,
    },
    args: ['-t', :filter, '-p', :tcp, '-m', 'tcp', '--tcp-flags', 'SYN,RST', 'SYN', '-j', 'TCPMSS', '--clamp-mss-to-pmtu', '-m', 'comment', '--comment', '067 change max segment size'],
  },
  'set_dscp_class' => {
    params: {
      name: '068 set dscp class to EF',
      table: 'mangle',
      proto: 'tcp',
      port: '997',
      jump: 'DSCP',
      set_dscp_class: 'ef',
    },
    args: ['-t', :mangle, '-p', :tcp, '-m', 'multiport', '--ports', '997', '-j', 'DSCP', '--set-dscp-class', 'ef', '-m', 'comment', '--comment', '068 set dscp class to EF'],
  },
  'length_1' => {
    params: {
      name: '000 length',
      table: 'filter',
      length: '42000',
    },
    args: ['-t', :filter, '-p', :tcp, '-m', 'length', '--length', '42000', '-m', 'comment', '--comment', '000 length'],
  },
  'length_2' => {
    params: {
      name: '000 length',
      table: 'filter',
      length: '1492-65535',
    },
    args: ['-t', :filter, '-p', :tcp, '-m', 'length', '--length', '1492:65535', '-m', 'comment', '--comment', '000 length'],
  },
  'string_matching_1' => {
    params: {
      name: '000 string_matching',
      table: 'filter',
      string: 'GET /index.html',
    },
    args: ['-t', :filter, '-p', :tcp, '-m', 'string', '--string', "GET /index.html", '-m', 'comment', '--comment', '000 string_matching'],
  },
  'string_matching_2' => {
    params: {
      name: '000 string_matching',
      table: 'filter',
      string: 'GET /index.html',
      string_algo: 'bm',
    },
    args: ['-t', :filter, '-p', :tcp, '-m', 'string', '--string', "GET /index.html", '--algo', :bm, '-m', 'comment', '--comment', '000 string_matching'],
  },
  'string_matching_3' => {
    params: {
      name: '000 string_matching',
      table: 'filter',
      string: 'GET /index.html',
      string_from: '1',
      string_to: '65535',
    },
    args: ['-t', :filter, '-p', :tcp, '-m', 'string', '--string', "GET /index.html", '--from', '1', '--to', '65535', '-m', 'comment', '--comment', '000 string_matching'],
  },
  'nfqueue_jump1' => {
    params: {
      name: '000 nfqueue specify queue_num',
      table: 'filter',
      jump: 'NFQUEUE',
      source: '1.2.3.4/32',
      destination: '4.3.2.1/32',
      queue_num: '50',
    },
    args: ['-t', :filter, '-s', '1.2.3.4/32', '-d', '4.3.2.1/32', '-p', :tcp, '-j', 'NFQUEUE', '--queue-num', '50', '-m', 'comment', '--comment', '000 nfqueue specify queue_num'],
  },
  'nfqueue_jump2' => {
    params: {
      name: '002 nfqueue specify queue_num and queue_bypass',
      table: 'filter',
      jump: 'NFQUEUE',
      source: '1.2.3.4/32',
      destination: '4.3.2.1/32',
      queue_num: '50',
      queue_bypass: true,
    },
    args: ['-t', :filter, '-s', '1.2.3.4/32', '-d', '4.3.2.1/32', '-p', :tcp, '-j', 'NFQUEUE', '--queue-num', '50', '--queue-bypass', '-m', 'comment', '--comment', '002 nfqueue specify queue_num and queue_bypass'], # rubocop:disable Layout/LineLength
  },
  'nfqueue_jump3' => {
    params: {
      name: '003 nfqueue dont specify queue_num or queue_bypass',
      table: 'filter',
      jump: 'NFQUEUE',
      source: '1.2.3.4/32',
      destination: '4.3.2.1/32',
    },
    args: ['-t', :filter, '-s', '1.2.3.4/32', '-d', '4.3.2.1/32', '-p', :tcp, '-j', 'NFQUEUE', '-m', 'comment', '--comment', '003 nfqueue dont specify queue_num or queue_bypass'],
  },
}.freeze
