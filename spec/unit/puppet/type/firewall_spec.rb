# frozen_string_literal: true

require 'spec_helper'
require 'puppet/type/firewall'

RSpec.describe 'firewall type' do
  let(:firewall) { Puppet::Type.type(:firewall) }

  it 'loads' do
    expect(firewall).not_to be_nil
  end

  it 'has :name be its namevar' do
    expect(firewall.key_attributes).to eql [:name]
  end

  describe ':line' do
    it 'is read only' do
      expect { firewall.new(name: '001 test rule', line: 'test') }.to raise_error(Puppet::Error)
    end
  end

  {
    ':ensure': {
      valid: [{ name: '001 test rule', ensure: 'present' }, { name: '001 test rule', ensure: 'absent' }],
      invalid: [{ name: '001 test rule', ensure: true }, { name: '001 test rule', ensure: 313 }, { name: '001 test rule', ensure: 'false' }]
    },
    ':name': {
      valid: [{ name: '001 first' }, { name: '202 second rule' }, { name: '333 third rule also' }],
      invalid: [{ name: 'invalid rule 001' }, { name: 'invalid rule two' }]
    },
    ':protocol': {
      valid: [{ name: '001 test rule', protocol: 'iptables' }, { name: '001 test rule', protocol: 'ip6tables' },
              { name: '001 test rule', protocol: 'IPv4' }, { name: '001 test rule', protocol: 'IPv6' }],
      invalid: [{ name: '001 test rule', protocol: true }, { name: '001 test rule', protocol: 313 },
                { name: '001 test rule', protocol: 'IPv6tables' }]
    },
    ':table': {
      valid: [{ name: '001 test rule', table: 'nat' }, { name: '001 test rule', table: 'raw' },
              { name: '001 test rule', table: 'broute' }, { name: '001 test rule', table: 'security' }],
      invalid: [{ name: '001 test rule', table: true }, { name: '001 test rule', table: 313 },
                { name: '001 test rule', table: 'rawroute' }]
    },
    ':chain': {
      valid: [{ name: '001 test rule', chain: 'INPUT' }, { name: '001 test rule', chain: 'OUTPUT' },
              { name: '001 test rule', chain: 'POSTROUTING' }, { name: '001 test rule', chain: 'test_chain' }],
      invalid: [{ name: '001 test rule', chain: true }, { name: '001 test rule', chain: 313 },
                { name: '001 test rule', chain: '' }]
    },
    ':source': {
      valid: [{ name: '001 test rule', source: '192.168.2.0/24' }, { name: '001 test rule', source: '! 192.168.2.0/24' },
              { name: '001 test rule', source: '1::46' }, { name: '001 test rule', source: '! 1::46' }],
      invalid: [{ name: '001 test rule', source: true }, { name: '001 test rule', source: 313 },
                { name: '001 test rule', source: '' }]
    },
    ':destination': {
      valid: [{ name: '001 test rule', destination: '192.168.2.0/24' }, { name: '001 test rule', destination: '! 192.168.2.0/24' },
              { name: '001 test rule', destination: '1::46' }, { name: '001 test rule', destination: '! 1::46' }],
      invalid: [{ name: '001 test rule', destination: true }, { name: '001 test rule', destination: 313 },
                { name: '001 test rule', destination: '' }]
    },
    ':iniface': {
      valid: [{ name: '001 test rule', iniface: 'enp0s8' }, { name: '001 test rule', iniface: '! enp0s8' },
              { name: '001 test rule', iniface: 'lo' }, { name: '001 test rule', iniface: '! lo' }],
      invalid: [{ name: '001 test rule', iniface: true }, { name: '001 test rule', iniface: 313 },
                { name: '001 test rule', iniface: 'invalid/' }, { name: '001 test rule', iniface: '' }]
    },
    ':outiface': {
      valid: [{ name: '001 test rule', outiface: 'enp0s8' }, { name: '001 test rule', outiface: '! enp0s8' },
              { name: '001 test rule', outiface: 'lo' }, { name: '001 test rule', outiface: '! lo' }],
      invalid: [{ name: '001 test rule', outiface: true }, { name: '001 test rule', outiface: 313 },
                { name: '001 test rule', outiface: 'invalid/' }, { name: '001 test rule', outiface: '' }]
    },
    ':physdev_in': {
      valid: [{ name: '001 test rule', physdev_in: 'enp0s8' }, { name: '001 test rule', physdev_in: '! enp0s8' },
              { name: '001 test rule', physdev_in: 'lo' }, { name: '001 test rule', physdev_in: '! lo' }],
      invalid: [{ name: '001 test rule', physdev_in: true }, { name: '001 test rule', physdev_in: 313 },
                { name: '001 test rule', physdev_in: 'invalid/' }, { name: '001 test rule', physdev_in: '' }]
    },
    ':physdev_out': {
      valid: [{ name: '001 test rule', physdev_out: 'enp0s8' }, { name: '001 test rule', physdev_out: '! enp0s8' },
              { name: '001 test rule', physdev_out: 'lo' }, { name: '001 test rule', physdev_out: '! lo' }],
      invalid: [{ name: '001 test rule', physdev_out: true }, { name: '001 test rule', physdev_out: 313 },
                { name: '001 test rule', physdev_out: 'invalid/' }, { name: '001 test rule', physdev_out: '' }]
    },
    ':physdev_is_bridged': {
      valid: [{ name: '001 test rule', physdev_is_bridged: true }, { name: '001 test rule', physdev_is_bridged: false }],
      invalid: [{ name: '001 test rule', physdev_is_bridged: 'invalid' }, { name: '001 test rule', physdev_is_bridged: 313 }]
    },
    ':physdev_is_in': {
      valid: [{ name: '001 test rule', physdev_is_in: true }, { name: '001 test rule', physdev_is_in: false }],
      invalid: [{ name: '001 test rule', physdev_is_in: 'invalid' }, { name: '001 test rule', physdev_is_in: 313 }]
    },
    ':physdev_is_out': {
      valid: [{ name: '001 test rule', physdev_is_out: true }, { name: '001 test rule', physdev_is_out: false }],
      invalid: [{ name: '001 test rule', physdev_is_out: 'invalid' }, { name: '001 test rule', physdev_is_out: 313 }]
    },
    ':proto': {
      valid: [{ name: '001 test rule', proto: 'ipencap' }, { name: '001 test rule', proto: 'gre' },
              { name: '001 test rule', proto: 'ip' }, { name: '001 test rule', proto: 'udp' }],
      invalid: [{ name: '001 test rule', proto: 'invalid' }, { name: '001 test rule', proto: 313 }]
    },
    ':isfragment': {
      valid: [{ name: '001 test rule', isfragment: true }, { name: '001 test rule', isfragment: false }],
      invalid: [{ name: '001 test rule', isfragment: 'invalid' }, { name: '001 test rule', isfragment: 313 }]
    },
    ':isfirstfrag': {
      valid: [{ name: '001 test rule', isfirstfrag: true }, { name: '001 test rule', isfirstfrag: false }],
      invalid: [{ name: '001 test rule', isfirstfrag: 'invalid' }, { name: '001 test rule', isfirstfrag: 313 }]
    },
    ':ishasmorefrags': {
      valid: [{ name: '001 test rule', ishasmorefrags: true }, { name: '001 test rule', ishasmorefrags: false }],
      invalid: [{ name: '001 test rule', ishasmorefrags: 'invalid' }, { name: '001 test rule', ishasmorefrags: 313 }]
    },
    ':islastfrag': {
      valid: [{ name: '001 test rule', islastfrag: true }, { name: '001 test rule', islastfrag: false }],
      invalid: [{ name: '001 test rule', islastfrag: 'invalid' }, { name: '001 test rule', islastfrag: 313 }]
    },
    ':stat_mode': {
      valid: [{ name: '001 test rule', stat_mode: 'nth' }, { name: '001 test rule', stat_mode: 'random' }],
      invalid: [{ name: '001 test rule', stat_mode: 'invalid' }, { name: '001 test rule', stat_mode: 313 }]
    },
    ':stat_every': {
      valid: [{ name: '001 test rule', stat_every: 1 }, { name: '001 test rule', stat_every: 313 }],
      invalid: [{ name: '001 test rule', stat_every: 'invalid' }, { name: '001 test rule', stat_every: false }]
    },
    ':stat_packet': {
      valid: [{ name: '001 test rule', stat_packet: 1 }, { name: '001 test rule', stat_packet: 313 }],
      invalid: [{ name: '001 test rule', stat_packet: 'invalid' }, { name: '001 test rule', stat_packet: false }]
    },
    ':stat_probability': {
      valid: [{ name: '001 test rule', stat_probability: 1 }, { name: '001 test rule', stat_probability: 0 },
              { name: '001 test rule', stat_probability: 0.15 }, { name: '001 test rule', stat_probability: 0.313 }],
      invalid: [{ name: '001 test rule', stat_probability: 'invalid' }, { name: '001 test rule', stat_probability: false },
                { name: '001 test rule', stat_probability: 15 }, { name: '001 test rule', stat_probability: 313 }]
    },
    ':src_range': {
      valid: [{ name: '001 test rule', src_range: '192.168.1.1-192.168.1.10' }, { name: '001 test rule', src_range: '! 192.168.1.1-192.168.1.10' },
              { name: '001 test rule', src_range: '1::46-2::48' }, { name: '001 test rule', src_range: '! 1::46-2::48' }],
      invalid: [{ name: '001 test rule', src_range: true }, { name: '001 test rule', src_range: 313 },
                { name: '001 test rule', src_range: '' }]
    },
    ':dst_range': {
      valid: [{ name: '001 test rule', dst_range: '192.168.1.1-192.168.1.10' }, { name: '001 test rule', dst_range: '! 192.168.1.1-192.168.1.10' },
              { name: '001 test rule', dst_range: '1::46-2::48' }, { name: '001 test rule', dst_range: '! 1::46-2::48' }],
      invalid: [{ name: '001 test rule', dst_range: true }, { name: '001 test rule', dst_range: 313 },
                { name: '001 test rule', dst_range: '' }]
    },
    ':tcp_option': {
      valid: [{ name: '001 test rule', tcp_option: '! 1' }, { name: '001 test rule', tcp_option: '15' },
              { name: '001 test rule', tcp_option: 121 }, { name: '001 test rule', tcp_option: '! 255' }],
      invalid: [{ name: '001 test rule', tcp_option: 'invalid' }, { name: '001 test rule', tcp_option: false },
                { name: '001 test rule', tcp_option: 313 }, { name: '001 test rule', tcp_option: '313' }]
    },
    ':tcp_flags': {
      valid: [{ name: '001 test rule', tcp_flags: 'FIN FIN,SYN,RST,ACK' }, { name: '001 test rule', tcp_flags: '! FIN,SYN,RST,ACK SYN' }],
      invalid: [{ name: '001 test rule', tcp_flags: 'invalid' }, { name: '001 test rule', tcp_flags: false },
                { name: '001 test rule', tcp_flags: 313 }, { name: '001 test rule', tcp_flags: 'FIN,SYN,RST,ACK' }]
    },
    ':uid': {
      valid: [{ name: '001 test rule', uid: 'testuser' }, { name: '001 test rule', uid: '! 0' },
              { name: '001 test rule', uid: 4 }, { name: '001 test rule', uid: 0 }],
      invalid: [{ name: '001 test rule', uid: 0.3 }, { name: '001 test rule', uid: false },
                { name: '001 test rule', uid: '' }]
    },
    ':gid': {
      valid: [{ name: '001 test rule', gid: 'testuser' }, { name: '001 test rule', gid: '! 0' },
              { name: '001 test rule', gid: 4 }, { name: '001 test rule', gid: 0 }],
      invalid: [{ name: '001 test rule', gid: 0.3 }, { name: '001 test rule', gid: false },
                { name: '001 test rule', gid: '' }]
    },
    ':mac_source': {
      valid: [{ name: '001 test rule', mac_source: 'FA:16:00:00:00:00' }, { name: '001 test rule', mac_source: '! FA:16:00:00:00:00' }],
      invalid: [{ name: '001 test rule', mac_source: 'FA1600000000' }, { name: '001 test rule', mac_source: false },
                { name: '001 test rule', mac_source: 1_600_000_000 }]
    },
    ':sport': {
      valid: [{ name: '001 test rule', sport: '1:1024' }, { name: '001 test rule', sport: '! 1-1024' },
              { name: '001 test rule', sport: 1024 }, { name: '001 test rule', sport: '! 1024' },
              { name: '001 test rule', sport: ['1:1024', '2024'] }, { name: '001 test rule', sport: ['! 1', 1024] }],
      invalid: [{ name: '001 test rule', sport: 'invalid' }, { name: '001 test rule', sport: false }]
    },
    ':dport': {
      valid: [{ name: '001 test rule', dport: '1:1024' }, { name: '001 test rule', dport: '! 1-1024' },
              { name: '001 test rule', dport: 1024 }, { name: '001 test rule', dport: '! 1024' },
              { name: '001 test rule', dport: ['1:1024', '1024'] }, { name: '001 test rule', dport: ['! 1', 1024] }],
      invalid: [{ name: '001 test rule', dport: 'invalid' }, { name: '001 test rule', dport: false }]
    },
    ':src_type': {
      valid: [{ name: '001 test rule', src_type: 'LOCAL' }, { name: '001 test rule', src_type: '! BROADCAST' },
              { name: '001 test rule', src_type: 'ANYCAST --limit-iface-in' },
              { name: '001 test rule', src_type: ['! LOCAL', 'PROHIBIT --limit-iface-in'] }],
      invalid: [{ name: '001 test rule', src_type: 'local' }, { name: '001 test rule', src_type: false },
                { name: '001 test rule', src_type: 123 }, { name: '001 test rule', src_type: ['unicast', 123] }]
    },
    ':dst_type': {
      valid: [{ name: '001 test rule', dst_type: 'LOCAL' }, { name: '001 test rule', dst_type: '! BROADCAST' },
              { name: '001 test rule', dst_type: 'ANYCAST --limit-iface-in' },
              { name: '001 test rule', dst_type: ['! LOCAL', 'PROHIBIT --limit-iface-in'] }],
      invalid: [{ name: '001 test rule', dst_type: 'local' }, { name: '001 test rule', dst_type: false },
                { name: '001 test rule', dst_type: 123 }, { name: '001 test rule', dst_type: ['unicast', 123] }]
    },
    ':socket': {
      valid: [{ name: '001 test rule', socket: true }, { name: '001 test rule', socket: false }],
      invalid: [{ name: '001 test rule', socket: 'invalid' }, { name: '001 test rule', socket: 313 }]
    },
    ':pkttype': {
      valid: [{ name: '001 test rule', pkttype: 'unicast' }, { name: '001 test rule', uid: 'broadcast' },
              { name: '001 test rule', pkttype: 'multicast' }],
      invalid: [{ name: '001 test rule', pkttype: 'invalid' }, { name: '001 test rule', pkttype: false },
                { name: '001 test rule', pkttype: 313 }]
    },
    ':ipsec_dir': {
      valid: [{ name: '001 test rule', ipsec_dir: 'in' }, { name: '001 test rule', ipsec_dir: 'out' }],
      invalid: [{ name: '001 test rule', ipsec_dir: 'invalid' }, { name: '001 test rule', ipsec_dir: false },
                { name: '001 test rule', ipsec_dir: 313 }]
    },
    ':ipsec_policy': {
      valid: [{ name: '001 test rule', ipsec_policy: 'none' }, { name: '001 test rule', ipsec_policy: 'ipsec' }],
      invalid: [{ name: '001 test rule', ipsec_policy: 'invalid' }, { name: '001 test rule', ipsec_policy: false },
                { name: '001 test rule', ipsec_policy: 313 }]
    },
    ':state': {
      valid: [{ name: '001 test rule', state: 'INVALID' }, { name: '001 test rule', state: '! ESTABLISHED' },
              { name: '001 test rule', state: ['! UNTRACKED', 'INVALID'] }],
      invalid: [{ name: '001 test rule', state: 'invalid' }, { name: '001 test rule', state: false }]
    },
    ':ctstate': {
      valid: [{ name: '001 test rule', ctstate: 'INVALID' }, { name: '001 test rule', ctstate: '! ESTABLISHED' },
              { name: '001 test rule', ctstate: ['! UNTRACKED', 'INVALID'] }],
      invalid: [{ name: '001 test rule', ctstate: 'invalid' }, { name: '001 test rule', ctstate: false }]
    },
    ':ctproto': {
      valid: [{ name: '001 test rule', ctproto: '! 1' }, { name: '001 test rule', ctproto: '15' },
              { name: '001 test rule', ctproto: 313 }, { name: '001 test rule', ctproto: '! 313' }],
      invalid: [{ name: '001 test rule', ctproto: 'invalid' }, { name: '001 test rule', ctproto: false }]
    },
    ':ctorigsrc': {
      valid: [{ name: '001 test rule', ctorigsrc: '192.168.2.0/24' }, { name: '001 test rule', ctorigsrc: '! 192.168.2.0/24' },
              { name: '001 test rule', ctorigsrc: '1::46' }, { name: '001 test rule', ctorigsrc: '! 1::46' }],
      invalid: [{ name: '001 test rule', ctorigsrc: true }, { name: '001 test rule', ctorigsrc: 313 },
                { name: '001 test rule', ctorigsrc: '' }]
    },
    ':ctorigdst': {
      valid: [{ name: '001 test rule', ctorigdst: '192.168.2.0/24' }, { name: '001 test rule', ctorigdst: '! 192.168.2.0/24' },
              { name: '001 test rule', ctorigdst: '1::46' }, { name: '001 test rule', ctorigdst: '! 1::46' }],
      invalid: [{ name: '001 test rule', ctorigdst: true }, { name: '001 test rule', ctorigdst: 313 },
                { name: '001 test rule', ctorigdst: '' }]
    },
    ':ctreplsrc': {
      valid: [{ name: '001 test rule', ctreplsrc: '192.168.2.0/24' }, { name: '001 test rule', ctreplsrc: '! 192.168.2.0/24' },
              { name: '001 test rule', ctreplsrc: '1::46' }, { name: '001 test rule', ctreplsrc: '! 1::46' }],
      invalid: [{ name: '001 test rule', ctreplsrc: true }, { name: '001 test rule', ctreplsrc: 313 },
                { name: '001 test rule', ctreplsrc: '' }]
    },
    ':ctrepldst': {
      valid: [{ name: '001 test rule', ctrepldst: '192.168.2.0/24' }, { name: '001 test rule', ctrepldst: '! 192.168.2.0/24' },
              { name: '001 test rule', ctrepldst: '1::46' }, { name: '001 test rule', ctrepldst: '! 1::46' }],
      invalid: [{ name: '001 test rule', ctrepldst: true }, { name: '001 test rule', ctrepldst: 313 },
                { name: '001 test rule', ctrepldst: '' }]
    },
    ':ctorigsrcport': {
      valid: [{ name: '001 test rule', ctorigsrcport: '80' }, { name: '001 test rule', ctorigsrcport: '! 80' },
              { name: '001 test rule', ctorigsrcport: '80:90' }, { name: '001 test rule', ctorigsrcport: '! 80:90' }],
      invalid: [{ name: '001 test rule', ctorigsrcport: true }, { name: '001 test rule', ctorigsrcport: 313 },
                { name: '001 test rule', ctorigsrcport: 'invalid' }]
    },
    ':ctorigdstport': {
      valid: [{ name: '001 test rule', ctorigdstport: '80' }, { name: '001 test rule', ctorigdstport: '! 80' },
              { name: '001 test rule', ctorigdstport: '80:90' }, { name: '001 test rule', ctorigdstport: '! 80:90' }],
      invalid: [{ name: '001 test rule', ctorigdstport: true }, { name: '001 test rule', ctorigdstport: 313 },
                { name: '001 test rule', ctorigdstport: 'invalid' }]
    },
    ':ctreplsrcport': {
      valid: [{ name: '001 test rule', ctreplsrcport: '80' }, { name: '001 test rule', ctreplsrcport: '! 80' },
              { name: '001 test rule', ctreplsrcport: '80:90' }, { name: '001 test rule', ctreplsrcport: '! 80:90' }],
      invalid: [{ name: '001 test rule', ctreplsrcport: true }, { name: '001 test rule', ctreplsrcport: 313 },
                { name: '001 test rule', ctreplsrcport: 'invalid' }]
    },
    ':ctrepldstport': {
      valid: [{ name: '001 test rule', ctrepldstport: '80' }, { name: '001 test rule', ctrepldstport: '! 80' },
              { name: '001 test rule', ctrepldstport: '80:90' }, { name: '001 test rule', ctrepldstport: '! 80:90' }],
      invalid: [{ name: '001 test rule', ctrepldstport: true }, { name: '001 test rule', ctrepldstport: 313 },
                { name: '001 test rule', ctrepldstport: 'invalid' }]
    },
    ':ctstatus': {
      valid: [{ name: '001 test rule', ctstatus: 'EXPECTED' }, { name: '001 test rule', ctstatus: '! CONFIRMED' },
              { name: '001 test rule', ctstatus: ['! EXPECTED', 'CONFIRMED'] }],
      invalid: [{ name: '001 test rule', ctstatus: 'invalid' }, { name: '001 test rule', ctstatus: false }]
    },
    ':ctexpire': {
      valid: [{ name: '001 test rule', ctexpire: '80' }, { name: '001 test rule', ctexpire: '80:160' }],
      invalid: [{ name: '001 test rule', ctexpire: true }, { name: '001 test rule', ctexpire: 313 },
                { name: '001 test rule', ctexpire: 'invalid' }]
    },
    ':ctdir': {
      valid: [{ name: '001 test rule', ctdir: 'REPLY' }, { name: '001 test rule', ctdir: 'ORIGINAL' }],
      invalid: [{ name: '001 test rule', ctstate: 'invalid' }, { name: '001 test rule', ctstate: false }]
    },
    ':hoplimit': {
      valid: [{ name: '001 test rule', hop_limit: '! 1' }, { name: '001 test rule', hop_limit: '15' },
              { name: '001 test rule', hop_limit: 313 }, { name: '001 test rule', hop_limit: '! 313' }],
      invalid: [{ name: '001 test rule', hop_limit: 'invalid' }, { name: '001 test rule', hop_limit: false }]
    },
    ':icmp': {
      valid: [{ name: '001 test rule', icmp: 'echo-reply' }, { name: '001 test rule', icmp: '15' },
              { name: '001 test rule', icmp: 313 }],
      invalid: [{ name: '001 test rule', icmp: true }, { name: '001 test rule', icmp: '' }]
    },
    ':limit': {
      valid: [{ name: '001 test rule', limit: '50/sec' }, { name: '001 test rule', limit: '50/second' },
              { name: '001 test rule', limit: '40/min' }, { name: '001 test rule', limit: '40/minute' },
              { name: '001 test rule', limit: '30/hour' }, { name: '001 test rule', limit: '10/day' }],
      invalid: [{ name: '001 test rule', limit: true }, { name: '001 test rule', limit: 30 },
                { name: '001 test rule', limit: 'invalid' }]
    },
    ':burst': {
      valid: [{ name: '001 test rule', burst: 1 }, { name: '001 test rule', burst: 313 }],
      invalid: [{ name: '001 test rule', burst: 'invalid' }, { name: '001 test rule', burst: false }]
    },
    ':length': {
      valid: [{ name: '001 test rule', length: '80' }, { name: '001 test rule', length: '80:90' }],
      invalid: [{ name: '001 test rule', length: true }, { name: '001 test rule', length: 313 },
                { name: '001 test rule', length: 'invalid' }]
    },
    ':recent': {
      valid: [{ name: '001 test rule', recent: 'set' }, { name: '001 test rule', recent: 'update' },
              { name: '001 test rule', recent: 'rcheck' }, { name: '001 test rule', recent: 'remove' },
              { name: '001 test rule', recent: '! set' }, { name: '001 test rule', recent: '! update' },
              { name: '001 test rule', recent: '! rcheck' }, { name: '001 test rule', recent: '! remove' }],
      invalid: [{ name: '001 test rule', recent: true }, { name: '001 test rule', recent: 30 },
                { name: '001 test rule', recent: 'invalid' }]
    },
    ':rseconds': {
      valid: [{ name: '001 test rule', rseconds: 1 }, { name: '001 test rule', rseconds: 313 }],
      invalid: [{ name: '001 test rule', rseconds: 'invalid' }, { name: '001 test rule', rseconds: false },
                { name: '001 test rule', rseconds: 0 }]
    },
    ':reap': {
      valid: [{ name: '001 test rule', reap: true }, { name: '001 test rule', reap: false }],
      invalid: [{ name: '001 test rule', reap: 'invalid' }, { name: '001 test rule', reap: 313 }]
    },
    ':rhitcount': {
      valid: [{ name: '001 test rule', rhitcount: 1 }, { name: '001 test rule', rhitcount: 313 }],
      invalid: [{ name: '001 test rule', rhitcount: 'invalid' }, { name: '001 test rule', rhitcount: false },
                { name: '001 test rule', rhitcount: 0 }]
    },
    ':rttl': {
      valid: [{ name: '001 test rule', rttl: true }, { name: '001 test rule', rttl: false }],
      invalid: [{ name: '001 test rule', rttl: 'invalid' }, { name: '001 test rule', rttl: 313 }]
    },
    ':rname': {
      valid: [{ name: '001 test rule', rname: 'list1' }, { name: '001 test rule', rname: 'list2' }],
      invalid: [{ name: '001 test rule', rname: true }, { name: '001 test rule', rname: 30 },
                { name: '001 test rule', rname: '' }]
    },
    ':mask': {
      valid: [{ name: '001 test rule', mask: '255.255.255.255' }, { name: '001 test rule', mask: '1.1.1.1' }],
      invalid: [{ name: '001 test rule', mask: true }, { name: '001 test rule', mask: 30 },
                { name: '001 test rule', mask: 'invalid' }]
    },
    ':rsource': {
      valid: [{ name: '001 test rule', rsource: true }, { name: '001 test rule', rsource: false }],
      invalid: [{ name: '001 test rule', rsource: 'invalid' }, { name: '001 test rule', rsource: 313 }]
    },
    ':rdest': {
      valid: [{ name: '001 test rule', rdest: true }, { name: '001 test rule', rdest: false }],
      invalid: [{ name: '001 test rule', rdest: 'invalid' }, { name: '001 test rule', rdest: 313 }]
    },
    ':ipset': {
      valid: [{ name: '001 test rule', ipset: 'setname1 src' }, { name: '001 test rule', ipset: '! setname2 dst' },
              { name: '001 test rule', ipset: ['setname1 src', '! setname2 dst'] }],
      invalid: [{ name: '001 test rule', ipset: 'invalid' }, { name: '001 test rule', ipset: false },
                { name: '001 test rule', ipset: false }]
    },
    ':string': {
      valid: [{ name: '001 test rule', string: 'GET /index.html' }],
      invalid: [{ name: '001 test rule', string: '' }, { name: '001 test rule', string: false },
                { name: '001 test rule', string: false }]
    },
    ':string_hex': {
      valid: [{ name: '001 test rule', string_hex: '|f4 6d 04 25 b2 02 00 0a|' }, { name: '001 test rule', string_hex: '! |0000ff0001|' }],
      invalid: [{ name: '001 test rule', string_hex: 'invalid' }, { name: '001 test rule', string_hex: false },
                { name: '001 test rule', string_hex: false }]
    },
    ':string_algo': {
      valid: [{ name: '001 test rule', string_algo: 'bm' }, { name: '001 test rule', string_algo: 'kmp' }],
      invalid: [{ name: '001 test rule', string_algo: 'invalid' }, { name: '001 test rule', string_algo: false },
                { name: '001 test rule', string_algo: false }]
    },
    ':string_from': {
      valid: [{ name: '001 test rule', string_from: 1 }, { name: '001 test rule', string_from: 313 }],
      invalid: [{ name: '001 test rule', string_from: 'invalid' }, { name: '001 test rule', string_from: false },
                { name: '001 test rule', string_from: 0 }]
    },
    ':string_to': {
      valid: [{ name: '001 test rule', string_to: 1 }, { name: '001 test rule', string_to: 313 }],
      invalid: [{ name: '001 test rule', string_to: 'invalid' }, { name: '001 test rule', string_to: false },
                { name: '001 test rule', string_to: 0 }]
    },
    ':jump': {
      valid: [{ name: '001 test rule', jump: 'QUEUE' }, { name: '001 test rule', jump: 'test_chain' }],
      invalid: [{ name: '001 test rule', jump: '' }, { name: '001 test rule', jump: false },
                { name: '001 test rule', jump: false }]
    },
    ':goto': {
      valid: [{ name: '001 test rule', goto: 'QUEUE' }, { name: '001 test rule', goto: 'test_chain' }],
      invalid: [{ name: '001 test rule', goto: '' }, { name: '001 test rule', goto: false },
                { name: '001 test rule', goto: false }]
    },
    ':clusterip_new': {
      valid: [{ name: '001 test rule', clusterip_new: true }, { name: '001 test rule', clusterip_new: false }],
      invalid: [{ name: '001 test rule', clusterip_new: 'invalid' }, { name: '001 test rule', clusterip_new: 313 }]
    },
    ':clusterip_hashmode': {
      valid: [{ name: '001 test rule', clusterip_hashmode: 'sourceip' }, { name: '001 test rule', clusterip_hashmode: 'sourceip-sourceport' },
              { name: '001 test rule', clusterip_hashmode: 'sourceip-sourceport-destport' }],
      invalid: [{ name: '001 test rule', clusterip_hashmode: 'invalid' }, { name: '001 test rule', clusterip_hashmode: false },
                { name: '001 test rule', clusterip_hashmode: false }]
    },
    ':clusterip_clustermac': {
      valid: [{ name: '001 test rule', clusterip_clustermac: 'FA:16:00:00:00:00' }],
      invalid: [{ name: '001 test rule', clusterip_clustermac: 'FA1600000000' }, { name: '001 test rule', clusterip_clustermac: false },
                { name: '001 test rule', clusterip_clustermac: 1_600_000_000 }]
    },
    ':clusterip_total_nodes': {
      valid: [{ name: '001 test rule', clusterip_total_nodes: 1 }, { name: '001 test rule', clusterip_total_nodes: 313 }],
      invalid: [{ name: '001 test rule', clusterip_total_nodes: 'invalid' }, { name: '001 test rule', clusterip_total_nodes: false }]
    },
    ':clusterip_local_node': {
      valid: [{ name: '001 test rule', clusterip_local_node: 1 }, { name: '001 test rule', clusterip_local_node: 313 }],
      invalid: [{ name: '001 test rule', clusterip_local_node: 'invalid' }, { name: '001 test rule', clusterip_local_node: false }]
    },
    ':clusterip_hash_init': {
      valid: [{ name: '001 test rule', clusterip_hash_init: 'random' }],
      invalid: [{ name: '001 test rule', clusterip_hash_init: '' }, { name: '001 test rule', clusterip_hash_init: false },
                { name: '001 test rule', clusterip_hash_init: 313 }]
    },
    ':queue_num': {
      valid: [{ name: '001 test rule', queue_num: 1 }, { name: '001 test rule', queue_num: 313 }],
      invalid: [{ name: '001 test rule', queue_num: 'invalid' }, { name: '001 test rule', queue_num: false },
                { name: '001 test rule', queue_num: 0 }]
    },
    ':queue_bypass': {
      valid: [{ name: '001 test rule', queue_bypass: true }, { name: '001 test rule', queue_bypass: false }],
      invalid: [{ name: '001 test rule', queue_bypass: 'invalid' }, { name: '001 test rule', queue_bypass: 313 }]
    },
    ':nflog_group': {
      valid: [{ name: '001 test rule', nflog_group: 1 }, { name: '001 test rule', queue_num: 313 }],
      invalid: [{ name: '001 test rule', nflog_group: 'invalid' }, { name: '001 test nflog_group', nflog_group: false },
                { name: '001 test rule', nflog_group: 0 }, { name: '001 test rule', nflog_group: 65_536 }]
    },
    ':nflog_prefix': {
      valid: [{ name: '001 test rule', nflog_prefix: 'Prefix Number One' }],
      invalid: [{ name: '001 test rule', nflog_prefix: 313 }, { name: '001 test rule', nflog_prefix: false }]
      # { name: '001 test rule', nflog_prefix: '' } attribute throws errors when type set to String[1]
    },
    ':nflog_range': {
      valid: [{ name: '001 test rule', nflog_range: 1 }, { name: '001 test rule', nflog_range: 313 }],
      invalid: [{ name: '001 test rule', nflog_range: 'invalid' }, { name: '001 test rule', nflog_range: false },
                { name: '001 test rule', nflog_range: 0 }]
    },
    ':nflog_size': {
      valid: [{ name: '001 test rule', nflog_size: 1 }, { name: '001 test rule', nflog_size: 313 }],
      invalid: [{ name: '001 test rule', nflog_size: 'invalid' }, { name: '001 test rule', nflog_size: false },
                { name: '001 test rule', nflog_size: 0 }]
    },
    ':nflog_threshold': {
      valid: [{ name: '001 test rule', nflog_threshold: 1 }, { name: '001 test rule', nflog_threshold: 313 }],
      invalid: [{ name: '001 test rule', nflog_threshold: 'invalid' }, { name: '001 test rule', nflog_threshold: false },
                { name: '001 test rule', nflog_threshold: 0 }]
    },
    ':gateway': {
      valid: [{ name: '001 test rule', gateway: '10.0.0.2' }, { name: '001 test rule', gateway: '2001:db1::1' }],
      invalid: [{ name: '001 test rule', gateway: 'invalid' }, { name: '001 test rule', gateway: false },
                { name: '001 test rule', gateway: false }]
    },
    ':clamp_mss_to_pmtu': {
      valid: [{ name: '001 test rule', clamp_mss_to_pmtu: true }, { name: '001 test rule', clamp_mss_to_pmtu: false }],
      invalid: [{ name: '001 test rule', clamp_mss_to_pmtu: 'invalid' }, { name: '001 test rule', clamp_mss_to_pmtu: 313 }]
    },
    ':set_mss': {
      valid: [{ name: '001 test rule', set_mss: 1 }, { name: '001 test rule', set_mss: 313 }],
      invalid: [{ name: '001 test rule', set_mss: 'invalid' }, { name: '001 test rule', set_mss: false },
                { name: '001 test rule', set_mss: 0 }]
    },
    ':set_dscp': {
      valid: [{ name: '001 test rule', set_dscp: '0x0a' }],
      invalid: [{ name: '001 test rule', set_dscp: '' }, { name: '001 test rule', set_dscp: false },
                { name: '001 test rule', set_dscp: 313 }]
    },
    ':set_dscp_class': {
      valid: [{ name: '001 test rule', set_dscp_class: 'af11' }, { name: '001 test rule', set_dscp_class: 'cs7' }],
      invalid: [{ name: '001 test rule', set_dscp_class: 'invalid' }, { name: '001 test rule', set_dscp_class: false },
                { name: '001 test rule', set_dscp_class: 313 }]
    },
    ':todest': {
      valid: [{ name: '001 test rule', todest: '10.0.0.2' }, { name: '001 test rule', todest: '10.0.0.2-10.0.0.3' },
              { name: '001 test rule', todest: '10.0.0.2:24' }, { name: '001 test rule', todest: '10.0.0.2-10.0.0.3:24-25' }],
      invalid: [{ name: '001 test rule', todest: '' }, { name: '001 test rule', todest: false },
                { name: '001 test rule', todest: 313 }]
    },
    ':tosource': {
      valid: [{ name: '001 test rule', tosource: '10.0.0.2' }, { name: '001 test rule', tosource: '10.0.0.2-10.0.0.3' },
              { name: '001 test rule', tosource: '10.0.0.2:24' }, { name: '001 test rule', tosource: '10.0.0.2-10.0.0.3:24-25' }],
      invalid: [{ name: '001 test rule', tosource: '' }, { name: '001 test rule', tosource: false },
                { name: '001 test rule', tosource: 313 }]
    },
    ':toports': {
      valid: [{ name: '001 test rule', toports: '40' }, { name: '001 test rule', tosource: '50-60' }],
      invalid: [{ name: '001 test rule', toports: 'invalid' }, { name: '001 test rule', toports: false },
                { name: '001 test rule', toports: 313 }]
    },
    ':to': {
      valid: [{ name: '001 test rule', to: '10.0.0.2' }, { name: '001 test rule', to: '10.0.0.2/24' }],
      invalid: [{ name: '001 test rule', to: '' }, { name: '001 test rule', to: false },
                { name: '001 test rule', to: 313 }]
    },
    ':checksum_fill': {
      valid: [{ name: '001 test rule', checksum_fill: true }, { name: '001 test rule', checksum_fill: false }],
      invalid: [{ name: '001 test rule', checksum_fill: 'invalid' }, { name: '001 test rule', checksum_fill: 313 }]
    },
    ':random_fully': {
      valid: [{ name: '001 test rule', random_fully: true }, { name: '001 test rule', random_fully: false }],
      invalid: [{ name: '001 test rule', random_fully: 'invalid' }, { name: '001 test rule', random_fully: 313 }]
    },
    ':random': {
      valid: [{ name: '001 test rule', random: true }, { name: '001 test rule', random: false }],
      invalid: [{ name: '001 test rule', random: 'invalid' }, { name: '001 test rule', random: 313 }]
    },
    ':log_prefix': {
      valid: [{ name: '001 test rule', log_prefix: 'Prefix Number One' }],
      invalid: [{ name: '001 test rule', log_prefix: 313 }, { name: '001 test rule', log_prefix: false },
                { name: '001 test rule', flog_prefix: '' }]
    },
    ':log_level': {
      valid: [{ name: '001 test rule', log_level: 'warn' }, { name: '001 test rule', log_level: 4 }],
      invalid: [{ name: '001 test rule', log_level: 313 }, { name: '001 test rule', log_level: false },
                { name: '001 test rule', log_level: '' }]
    },
    ':log_uid': {
      valid: [{ name: '001 test rule', log_uid: true }, { name: '001 test rule', log_uid: false }],
      invalid: [{ name: '001 test rule', log_uid: 'invalid' }, { name: '001 test rule', log_uid: 313 }]
    },
    ':log_tcp_sequence': {
      valid: [{ name: '001 test rule', log_tcp_sequence: true }, { name: '001 test rule', log_tcp_sequence: false }],
      invalid: [{ name: '001 test rule', log_tcp_sequence: 'invalid' }, { name: '001 test rule', log_tcp_sequence: 313 }]
    },
    ':log_tcp_options': {
      valid: [{ name: '001 test rule', log_tcp_options: true }, { name: '001 test rule', log_tcp_options: false }],
      invalid: [{ name: '001 test rule', log_tcp_options: 'invalid' }, { name: '001 test rule', log_tcp_options: 313 }]
    },
    ':log_ip_options': {
      valid: [{ name: '001 test rule', log_ip_options: true }, { name: '001 test rule', log_ip_options: false }],
      invalid: [{ name: '001 test rule', log_ip_options: 'invalid' }, { name: '001 test rule', log_ip_options: 313 }]
    },
    ':reject': {
      valid: [{ name: '001 test rule', reject: 'icmp-net-unreachable' }, { name: '001 test rule', reject: 'icmp-proto-unreachable' },
              { name: '001 test rule', reject: 'icmp-admin-prohibited' }, { name: '001 test rule', reject: 'icmp6-port-unreachable' }],
      invalid: [{ name: '001 test rule', reject: 'invalid' }, { name: '001 test rule', reject: false },
                { name: '001 test rule', reject: 313 }]
    },
    ':set_mark': {
      valid: [{ name: '001 test rule', set_mark: '0x3e8' }, { name: '001 test rule', set_mark: '0x3e8/0xffffffff' }],
      invalid: [{ name: '001 test rule', set_mark: 'invalid' }, { name: '001 test rule', set_mark: false },
                { name: '001 test rule', set_mark: 313 }]
    },
    ':match_mark': {
      valid: [{ name: '001 test rule', match_mark: '0x1' }, { name: '001 test rule', match_mark: '! 0x1' }],
      invalid: [{ name: '001 test rule', match_mark: 'invalid' }, { name: '001 test rule', match_mark: false },
                { name: '001 test rule', match_mark: 313 }]
    },
    ':mss': {
      valid: [{ name: '001 test rule', mss: '1361:1541' }, { name: '001 test rule', mss: '! 1361' },
              { name: '001 test rule', mss: '1361:1541' }, { name: '001 test rule', mss: '! 1361:1541' }],
      invalid: [{ name: '001 test rule', mss: 'invalid' }, { name: '001 test rule', mss: false },
                { name: '001 test rule', mss: 313 }]
    },
    ':connlimit_upto': {
      valid: [{ name: '001 test rule', connlimit_upto: 1 }, { name: '001 test rule', connlimit_upto: 313 }],
      invalid: [{ name: '001 test rule', connlimit_upto: 'invalid' }, { name: '001 test rule', connlimit_upto: false }]
    },
    ':connlimit_above': {
      valid: [{ name: '001 test rule', connlimit_above: 1 }, { name: '001 test rule', connlimit_above: 313 }],
      invalid: [{ name: '001 test rule', connlimit_above: 'invalid' }, { name: '001 test rule', connlimit_above: false }]
    },
    ':connlimit_mask': {
      valid: [{ name: '001 test rule', connlimit_mask: 1 }, { name: '001 test rule', connlimit_mask: 128 }],
      invalid: [{ name: '001 test rule', connlimit_mask: 'invalid' }, { name: '001 test rule', connlimit_mask: false },
                { name: '001 test rule', connlimit_mask: 313 }]
    },
    ':connmark': {
      valid: [{ name: '001 test rule', connmark: '0x1' }, { name: '001 test rule', connmark: '! 0x1' }],
      invalid: [{ name: '001 test rule', connmark: 'invalid' }, { name: '001 test rule', connmark: false },
                { name: '001 test rule', connmark: 313 }]
    },
    ':time_start': {
      valid: [{ name: '001 test rule', time_start: '23:59:59' }, { name: '001 test rule', time_start: '03:59' }],
      invalid: [{ name: '001 test rule', time_start: '26:70:70' }, { name: '001 test rule', time_start: false },
                { name: '001 test rule', time_start: 313 }]
    },
    ':time_stop': {
      valid: [{ name: '001 test rule', time_stop: '23:59:59' }, { name: '001 test rule', time_stop: '03:59' }],
      invalid: [{ name: '001 test rule', time_stop: '26:70:70' }, { name: '001 test rule', time_stop: false },
                { name: '001 test rule', time_stop: 313 }]
    },
    ':month_days': {
      valid: [{ name: '001 test rule', month_days: 1 }, { name: '001 test rule', month_days: [3, 1, 3] }],
      invalid: [{ name: '001 test rule', month_days: 'invalid' }, { name: '001 test rule', month_days: false },
                { name: '001 test rule', month_days: 313 }, { name: '001 test rule', month_days: [313, 619] }]
    },
    ':date_start': {
      valid: [{ name: '001 test rule', date_start: '1970-01-01T00:00:00' }, { name: '001 test rule', date_start: '2023-08-08T15:18:00' }],
      invalid: [{ name: '001 test rule', date_start: '1690-00-00T70:70:70' }, { name: '001 test rule', date_start: false },
                { name: '001 test rule', date_start: 313 }, { name: '001 test rule', date_start: 'invalid' }]
    },
    ':date_stop': {
      valid: [{ name: '001 test rule', date_stop: '1970-01-01T00:00:00' }, { name: '001 test rule', date_stop: '2023-08-08T15:18:00' }],
      invalid: [{ name: '001 test rule', date_stop: '1690-00-00T70:70:70' }, { name: '001 test rule', date_stop: false },
                { name: '001 test rule', date_stop: 313 }, { name: '001 test rule', date_stop: 'invalid' }]
    },
    ':kernel_timezone': {
      valid: [{ name: '001 test rule', kernel_timezone: true }, { name: '001 test rule', kernel_timezone: false }],
      invalid: [{ name: '001 test rule', kernel_timezone: 'invalid' }, { name: '001 test rule', kernel_timezone: 313 }]
    },
    ':u32': {
      valid: [{ name: '001 test rule', u32: '0x4&0x1fff=0x0&&0x0&0xf000000=0x5000000' }],
      invalid: [{ name: '001 test rule', u32: 'invalid' }, { name: '001 test rule', u32: false },
                { name: '001 test rule', u32: 313 }]
    },
    ':src_cc': {
      valid: [{ name: '001 test rule', src_cc: 'GB' }, { name: '001 test rule', src_cc: 'GB,US' }],
      invalid: [{ name: '001 test rule', src_cc: 'invalid' }, { name: '001 test rule', src_cc: false },
                { name: '001 test rule', src_cc: 313 }]
    },
    ':dst_cc': {
      valid: [{ name: '001 test rule', dst_cc: 'GB' }, { name: '001 test rule', dst_cc: 'GB,US' }],
      invalid: [{ name: '001 test rule', dst_cc: 'invalid' }, { name: '001 test rule', dst_cc: false },
                { name: '001 test rule', dst_cc: 313 }]
    },
    ':hashlimit_upto': {
      valid: [{ name: '001 test rule', hashlimit_upto: '50/sec' }, { name: '001 test rule', hashlimit_upto: '40/min' },
              { name: '001 test rule', hashlimit_upto: '30/hour' }, { name: '001 test rule', hashlimit_upto: '10/day' }],
      invalid: [{ name: '001 test rule', hashlimit_upto: true }, { name: '001 test rule', hashlimit_upto: 30 },
                { name: '001 test rule', hashlimit_upto: 'invalid' }]
    },
    ':hashlimit_above': {
      valid: [{ name: '001 test rule', hashlimit_above: '50/sec' }, { name: '001 test rule', hashlimit_above: '40/min' },
              { name: '001 test rule', hashlimit_above: '30/hour' }, { name: '001 test rule', hashlimit_above: '10/day' }],
      invalid: [{ name: '001 test rule', hashlimit_above: true }, { name: '001 test rule', hashlimit_above: 30 },
                { name: '001 test rule', hashlimit_above: 'invalid' }]
    },
    ':hashlimit_name': {
      valid: [{ name: '001 test rule', hashlimit_name: 'above' }, { name: '001 test rule', hashlimit_name: 'upto' }],
      invalid: [{ name: '001 test rule', hashlimit_name: true }, { name: '001 test rule', hashlimit_name: 30 },
                { name: '001 test rule', hashlimit_name: '' }]
    },
    ':hashlimit_burst': {
      valid: [{ name: '001 test rule', hashlimit_burst: 1 }, { name: '001 test rule', hashlimit_burst: 313 }],
      invalid: [{ name: '001 test rule', hashlimit_burst: 'invalid' }, { name: '001 test rule', hashlimit_burst: false }]
    },
    ':hashlimit_mode': {
      valid: [{ name: '001 test rule', hashlimit_mode: 'srcip' }, { name: '001 test rule', hashlimit_mode: 'srcip,srcport,dstip,dstport' }],
      invalid: [{ name: '001 test rule', hashlimit_mode: true }, { name: '001 test rule', hashlimit_mode: 30 },
                { name: '001 test rule', hashlimit_mode: 'invalid' }]
    },
    ':hashlimit_srcmask': {
      valid: [{ name: '001 test rule', hashlimit_srcmask: 1 }, { name: '001 test rule', hashlimit_srcmask: 32 }],
      invalid: [{ name: '001 test rule', hashlimit_srcmask: 'invalid' }, { name: '001 test rule', hashlimit_srcmask: false },
                { name: '001 test rule', hashlimit_mode: 33 }]
    },
    ':hashlimit_dstmask': {
      valid: [{ name: '001 test rule', hashlimit_dstmask: 1 }, { name: '001 test rule', hashlimit_dstmask: 32 }],
      invalid: [{ name: '001 test rule', hashlimit_dstmask: 'invalid' }, { name: '001 test rule', hashlimit_dstmask: false },
                { name: '001 test rule', hashlimit_dstmask: 33 }]
    },
    ':hashlimit_htable_size': {
      valid: [{ name: '001 test rule', hashlimit_htable_size: 1 }, { name: '001 test rule', hashlimit_htable_size: 313 }],
      invalid: [{ name: '001 test rule', hashlimit_htable_size: 'invalid' }, { name: '001 test rule', hashlimit_htable_size: false }]
    },
    ':hashlimit_htable_max': {
      valid: [{ name: '001 test rule', hashlimit_htable_max: 1 }, { name: '001 test rule', hashlimit_htable_max: 313 }],
      invalid: [{ name: '001 test rule', hashlimit_htable_max: 'invalid' }, { name: '001 test rule', hashlimit_htable_max: false }]
    },
    ':hashlimit_htable_expire': {
      valid: [{ name: '001 test rule', hashlimit_htable_expire: 1 }, { name: '001 test rule', hashlimit_htable_expire: 313 }],
      invalid: [{ name: '001 test rule', hashlimit_htable_expire: 'invalid' }, { name: '001 test rule', hashlimit_htable_expire: false }]
    },
    ':hashlimit_htable_gcinterval': {
      valid: [{ name: '001 test rule', hashlimit_htable_gcinterval: 1 }, { name: '001 test rule', hashlimit_htable_gcinterval: 313 }],
      invalid: [{ name: '001 test rule', hashlimit_htable_gcinterval: 'invalid' }, { name: '001 test rule', hashlimit_htable_gcinterval: false }]
    },
    ':bytecode': {
      valid: [{ name: '001 test rule', bytecode: '4,48 0 0 9,21 0 1 6,6 0 0 1,6 0 0 0' }],
      invalid: [{ name: '001 test rule', bytecode: 313 }, { name: '001 test rule', bytecode: false },
                { name: '001 test rule', bytecode: '' }]
    },
    ':ipvs': {
      valid: [{ name: '001 test rule', ipvs: true }, { name: '001 test rule', ipvs: false }],
      invalid: [{ name: '001 test rule', ipvs: 'invalid' }, { name: '001 test rule', ipvs: 313 }]
    },
    ':zone': {
      valid: [{ name: '001 test rule', zone: 1 }, { name: '001 test rule', zone: 313 }],
      invalid: [{ name: '001 test rule', zone: 'invalid' }, { name: '001 test rule', zone: false }]
    },
    ':helper': {
      valid: [{ name: '001 test rule', helper: 'helperOne' }],
      invalid: [{ name: '001 test rule', helper: 313 }, { name: '001 test rule', helper: false },
                { name: '001 test rule', helper: '' }]
    },
    ':cgroup': {
      valid: [{ name: '001 test rule', cgroup: '0x100001' }],
      invalid: [{ name: '001 test rule', cgroup: 313 }, { name: '001 test rule', cgroup: false },
                { name: '001 test rule', cgroup: '' }]
    },
    ':rpfilter': {
      valid: [{ name: '001 test rule', rpfilter: 'loose' }, { name: '001 test rule', rpfilter: 'accept-local' },
              { name: '001 test rule', rpfilter: ['validmark', 'invert'] }],
      invalid: [{ name: '001 test rule', rpfilter: 'invalid' }, { name: '001 test rule', rpfilter: false },
                { name: '001 test rule', rpfilter: false }]
    },
    ':condition': {
      valid: [{ name: '001 test rule', condition: 'isblue' }, { name: '001 test rule', condition: '! isblue' }],
      invalid: [{ name: '001 test rule', condition: 313 }, { name: '001 test rule', condition: false },
                { name: '001 test rule', condition: '' }]
    },
    ':notrack': {
      valid: [{ name: '001 test rule', notrack: true }, { name: '001 test rule', notrack: false }],
      invalid: [{ name: '001 test rule', notrack: 'invalid' }, { name: '001 test rule', notrack: 313 }]
    }
  }.each do |attribute|
    describe attribute[0] do
      context 'when given a valid value' do
        attribute[1][:valid].each do |valid_input|
          it valid_input do
            expect { firewall.new(valid_input) }.not_to raise_error
          end
        end
      end

      context 'when given an invalid value' do
        attribute[1][:invalid].each do |invalid_input|
          it invalid_input do
            expect { firewall.new(invalid_input) }.to raise_error(Puppet::Error)
          end
        end
      end
    end
  end
end
