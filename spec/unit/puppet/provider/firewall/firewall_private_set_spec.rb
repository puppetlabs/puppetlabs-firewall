# frozen_string_literal: true

require 'spec_helper'
require 'puppet/resource_api'

ensure_module_defined('Puppet::Provider::Firewall')
require 'puppet/provider/firewall/firewall'

RSpec.describe Puppet::Provider::Firewall::Firewall do
  describe 'Private Methods - Set' do
    subject(:provider) { described_class }

    let(:type) { Puppet::Type.type('firewall') }
    let(:context) { Puppet::ResourceApi::BaseContext.new(type.type_definition.definition) }

    describe 'self.validate_input(_is, should)' do
      [
        {
          valid: { is: {}, should: { ensure: 'present', name: '001 Test Rule' } },
          invalid: { is: {}, should: { ensure: 'present', name: '9001 Test Rule' } },
          error: 'Rule name cannot start with 9000-9999, as this range is reserved for unmanaged rules.'
        },
        {
          valid: { is: {}, should: { ensure: 'present', name: '001 Test Rule', proto: 'tcp', isfragment: true } },
          invalid: { is: {}, should: { ensure: 'present', name: '001 Test Rule', proto: 'all', isfragment: true } },
          error: '`proto` must be set to `tcp` for `isfragment` to be true.'
        },
        {
          valid: { is: {}, should: { ensure: 'present', name: '001 Test Rule', stat_mode: 'nth', stat_every: 313 } },
          invalid: { is: {}, should: { ensure: 'present', name: '001 Test Rule', stat_mode: 'random', stat_every: 313 } },
          error: '`stat_mode` must be set to `nth` for `stat_every` to be set.'
        },
        {
          valid: { is: {}, should: { ensure: 'present', name: '001 Test Rule', stat_mode: 'nth', stat_packet: 313 } },
          invalid: { is: {}, should: { ensure: 'present', name: '001 Test Rule', stat_packet: 313 } },
          error: '`stat_mode` must be set to `nth` for `stat_packet` to be set.'
        },
        {
          valid: { is: {}, should: { ensure: 'present', name: '001 Test Rule', stat_mode: 'random', stat_probability: 0.5 } },
          invalid: { is: {}, should: { ensure: 'present', name: '001 Test Rule', stat_mode: 'nth', stat_probability: 0.5 } },
          error: '`stat_mode` must be set to `random` for `stat_probability` to be set.'
        },
        {
          # Covers `dport`, `sport`, `state`, `ctstate` and `ctstatus`
          valid: { is: {}, should: { ensure: 'present', name: '001 Test Rule', dport: ['! 54', '64', '74'] } },
          invalid: { is: {}, should: { ensure: 'present', name: '001 Test Rule', dport: ['54', '! 64', '74'] } },
          error: 'When negating a `dport` array, you must negate either the first given value only or all the given values.'
        },
        {
          # Covers `dport`, `sport`, `state`, `ctstate` and `ctstatus`
          valid: { is: {}, should: { ensure: 'present', name: '001 Test Rule', sport: ['! 54', '! 64', '! 74'] } },
          invalid: { is: {}, should: { ensure: 'present', name: '001 Test Rule', sport: ['! 54', '! 64', '74'] } },
          error: 'When negating a `sport` array, you must negate either the first given value only or all the given values.'
        },
        {
          valid: { is: {}, should: { ensure: 'present', name: '001 Test Rule' } },
          invalid: { is: {}, should: { ensure: 'present', name: '001 Test Rule', icmp: 'any' } },
          error: 'Value `any` is not valid. This behaviour should be achieved by omitting or undefining the ICMP parameter.'
        },
        {
          valid: { is: {}, should: { ensure: 'present', name: '001 Test Rule', limit: '50/sec', burst: 313 } },
          invalid: { is: {}, should: { ensure: 'present', name: '001 Test Rule', burst: 313 } },
          error: '`burst` cannot be set without `limit`.'
        },
        {
          valid: { is: {}, should: { ensure: 'present', name: '001 Test Rule', length: 313 } },
          invalid: { is: {}, should: { ensure: 'present', name: '001 Test Rule', length: 65_536 } },
          error: '`length` values must be between 0 and 65535'
        },
        {
          valid: { is: {}, should: { ensure: 'present', name: '001 Test Rule', recent: 'rcheck', rseconds: 313 } },
          invalid: { is: {}, should: { ensure: 'present', name: '001 Test Rule', recent: 'remove', rseconds: 313 } },
          error: '`recent` must be set to `update` or `rcheck` for `rseconds` to be set.'
        },
        {
          valid: { is: {}, should: { ensure: 'present', name: '001 Test Rule', recent: 'rcheck', rseconds: 313, reap: true } },
          invalid: { is: {}, should: { ensure: 'present', name: '001 Test Rule', recent: 'rcheck', reap: true } },
          error: '`rseconds` must be set for `reap` to be set.'
        },
        {
          valid: { is: {}, should: { ensure: 'present', name: '001 Test Rule', recent: 'rcheck', rhitcount: 313 } },
          invalid: { is: {}, should: { ensure: 'present', name: '001 Test Rule', recent: 'remove', rhitcount: 313 } },
          error: '`recent` must be set to `update` or `rcheck` for `rhitcount` to be set.'
        },
        {
          valid: { is: {}, should: { ensure: 'present', name: '001 Test Rule', recent: 'update', rttl: true } },
          invalid: { is: {}, should: { ensure: 'present', name: '001 Test Rule', recent: 'remove', rttl: true } },
          error: '`recent` must be set to `update` or `rcheck` for `rttl` to be set.'
        },
        {
          valid: { is: {}, should: { ensure: 'present', name: '001 Test Rule', recent: 'rcheck', rname: 'test' } },
          invalid: { is: {}, should: { ensure: 'present', name: '001 Test Rule', rname: 'test' } },
          error: '`recent` must be set for `rname` to be set.'
        },
        {
          valid: { is: {}, should: { ensure: 'present', name: '001 Test Rule', recent: 'rcheck', rsource: 'test' } },
          invalid: { is: {}, should: { ensure: 'present', name: '001 Test Rule', rsource: 'test' } },
          error: '`recent` must be set for `rsource` to be set.'
        },
        {
          valid: { is: {}, should: { ensure: 'present', name: '001 Test Rule', recent: 'rcheck', rdest: 'test' } },
          invalid: { is: {}, should: { ensure: 'present', name: '001 Test Rule', rdest: 'test' } },
          error: '`recent` must be set for `rdest` to be set.'
        },
        {
          valid: { is: {}, should: { ensure: 'present', name: '001 Test Rule', recent: 'update', rsource: 'test' } },
          invalid: { is: {}, should: { ensure: 'present', name: '001 Test Rule', recent: 'update', rsource: 'test', rdest: 'test' } },
          error: '`rdest` and `rsource` are mutually exclusive, only one may be set at a time.'
        },
        {
          valid: { is: {}, should: { ensure: 'present', name: '001 Test Rule', string_algo: 'bm', string_hex: 'test', string: 'test' } },
          invalid: { is: {}, should: { ensure: 'present', name: '001 Test Rule', string_hex: 'test', string: 'test' } },
          error: '`string_algo` must be set for `string` or `string_hex` to be set.'
        },
        {
          valid: { is: {}, should: { ensure: 'present', name: '001 Test Rule', queue_num: 313 } },
          invalid: { is: {}, should: { ensure: 'present', name: '001 Test Rule', queue_num: 65_536 } },
          error: '`queue_num`` must be between 0 and 65535'
        },
        {
          # `2^16-1` is equal to `65_535`
          valid: { is: {}, should: { ensure: 'present', name: '001 Test Rule', nflog_group: 313 } },
          invalid: { is: {}, should: { ensure: 'present', name: '001 Test Rule', nflog_group: 65_536 } },
          error: '`nflog_group` must be between 0 and 2^16-1'
        },
        {
          valid: { is: {}, should: { ensure: 'present', name: '001 Test Rule', jump: 'TEE', gateway: '0.0.0.0' } },
          invalid: { is: {}, should: { ensure: 'present', name: '001 Test Rule', jump: 'TEE' } },
          error: 'When setting `jump => TEE`, the gateway property is required'
        },
        {
          valid: { is: {}, should: { ensure: 'present', name: '001 Test Rule', jump: 'TCPMSS', set_mss: 313 } },
          invalid: { is: {}, should: { ensure: 'present', name: '001 Test Rule', jump: 'TCPMSS' } },
          error: 'When setting `jump => TCPMSS`, the `set_mss` or `clamp_mss_to_pmtu` property is required'
        },
        {
          valid: { is: {}, should: { ensure: 'present', name: '001 Test Rule', jump: 'DSCP', set_dscp_class: 'af11' } },
          invalid: { is: {}, should: { ensure: 'present', name: '001 Test Rule', jump: 'DSCP' } },
          error: 'When setting `jump => DSCP`, the `set_dscp` or `set_dscp_class` property is required'
        },
        {
          valid: { is: {}, should: { ensure: 'present', name: '001 Test Rule', jump: 'DNAT', todest: '0.0.0.0', table: 'nat' } },
          invalid: { is: {}, should: { ensure: 'present', name: '001 Test Rule', jump: 'DNAT', todest: '0.0.0.0', table: 'filter' } },
          error: 'Parameter `jump => DNAT` only applies to `table => nat`'
        },
        {
          valid: { is: {}, should: { ensure: 'present', name: '001 Test Rule', jump: 'DNAT', table: 'nat', todest: '0.0.0.0' } },
          invalid: { is: {}, should: { ensure: 'present', name: '001 Test Rule', jump: 'DNAT', table: 'nat' } },
          error: 'Parameter `jump => DNAT` must have `todest` parameter'
        },
        {
          valid: { is: {}, should: { ensure: 'present', name: '001 Test Rule', jump: 'SNAT', tosource: '0.0.0.0', table: 'nat' } },
          invalid: { is: {}, should: { ensure: 'present', name: '001 Test Rule', jump: 'SNAT', tosource: '0.0.0.0', table: 'filter' } },
          error: 'Parameter `jump => SNAT` only applies to `table => nat`'
        },
        {
          valid: { is: {}, should: { ensure: 'present', name: '001 Test Rule', jump: 'SNAT', table: 'nat', tosource: '0.0.0.0' } },
          invalid: { is: {}, should: { ensure: 'present', name: '001 Test Rule', jump: 'SNAT', table: 'nat' } },
          error: 'Parameter `jump => SNAT` must have `tosource` parameter'
        },
        {
          valid: { is: {}, should: { ensure: 'present', name: '001 Test Rule', jump: 'CHECKSUM', table: 'mangle', checksum_fill: true } },
          invalid: { is: {}, should: { ensure: 'present', name: '001 Test Rule', table: 'filter', checksum_fill: true } },
          error: 'Parameter `checksum_fill` requires `jump => CHECKSUM` and `table => mangle`'
        },
        {
          # Covers `log_prefix`, `log_level`, `log_uid`, `log_tcp_sequence`, `log_tcp_options` and `log_ip_options`
          valid: { is: {}, should: { ensure: 'present', name: '001 Test Rule', jump: 'LOG', log_prefix: 'Test prefix' } },
          invalid: { is: {}, should: { ensure: 'present', name: '001 Test Rule', jump: 'CHECKSUM', log_prefix: 'Test prefix' } },
          error: 'Parameter `log_prefix` requires `jump => LOG`'
        },
        {
          valid: { is: {}, should: { ensure: 'present', name: '001 Test Rule', table: 'raw', jump: 'CT' } },
          invalid: { is: {}, should: { ensure: 'present', name: '001 Test Rule', table: 'filter', jump: 'CT' } },
          error: 'Parameter `jump => CT` only applies to `table => raw`'
        },
        {
          valid: { is: {}, should: { ensure: 'present', name: '001 Test`` Rule', table: 'raw', jump: 'CT', zone: 313 } },
          invalid: { is: {}, should: { ensure: 'present', name: '001 Test Rule', table: 'filter', zone: 313 } },
          error: 'Parameter `zone` requires `jump => CT`'
        },
        {
          valid: { is: {}, should: { ensure: 'present', name: '001 Test`` Rule', table: 'raw', jump: 'CT', helper: 'helperOne' } },
          invalid: { is: {}, should: { ensure: 'present', name: '001 Test Rule', table: 'filter', helper: 'helperOne' } },
          error: 'Parameter `helper` requires `jump => CT`'
        },
        {
          valid: { is: {}, should: { ensure: 'present', name: '001 Test`` Rule', table: 'raw', jump: 'CT', notrack: true } },
          invalid: { is: {}, should: { ensure: 'present', name: '001 Test Rule', table: 'filter', notrack: true } },
          error: 'Parameter `notrack` requires `jump => CT`'
        },
        {
          valid: { is: {}, should: { ensure: 'present', name: '001 Test`` Rule', connlimit_mask: 32, connlimit_upto: 5 } },
          invalid: { is: {}, should: { ensure: 'present', name: '001 Test Rule', connlimit_mask: 32 } },
          error: 'Parameter `connlimit_mask` requires either `connlimit_upto` or `connlimit_above`'
        },
        {
          # Covers `hashlimit_upto`, `hashlimit_above`, `hashlimit_name`, `hashlimit_burst`, `hashlimit_mode`, `hashlimit_srcmask`,
          # `hashlimit_dstmask`, `hashlimit_htable_size`, `hashlimit_htable_max`, `hashlimit_htable_expire` and `hashlimit_htable_gcinterval`
          valid: { is: {}, should: { ensure: 'present', name: '001 Test Rule', hashlimit_name: 'hashlimit test', hashlimit_upto: '40/min' } },
          invalid: { is: {}, should: { ensure: 'present', name: '001 Test Rule', hashlimit_upto: '40/min' } },
          error: 'Parameter `hashlimit_name` and either `hashlimit_upto` or `hashlimit_above` are required when setting any `hashlimit` attribute.'
        },
        {
          valid: { is: {}, should: { ensure: 'present', name: '001 Test Rule', hashlimit_name: 'hashlimit test', hashlimit_upto: '40/min' } },
          invalid: { is: {}, should: { ensure: 'present', name: '001 Test Rule', hashlimit_name: 'hashlimit test', hashlimit_upto: '40/min', hashlimit_above: '40/min' } },
          error: '`hashlimit_upto` and `hashlimit_above` are mutually exclusive, only one may be set at a time.'
        },
        {
          # Covers `clusterip_new`, `clusterip_hashmode`, `clusterip_clustermac`, `clusterip_total_nodes`, `clusterip_local_node`, `clusterip_hash_init`
          valid: { is: {}, should: { ensure: 'present', name: '001 Test Rule', protocol: 'IPv4', clusterip_new: true } },
          invalid: { is: {}, should: { ensure: 'present', name: '001 Test Rule', protocol: 'IPv6', clusterip_new: true } },
          error: 'Parameter `clusterip_new` is specific to the `IPv4` protocol'
        },
        {
          # Covers `hop_limit`, `ishasmorefrags`, `islastfrag`, `isfirstfrag`
          valid: { is: {}, should: { ensure: 'present', name: '001 Test Rule', protocol: 'ip6tables', islastfrag: true } },
          invalid: { is: {}, should: { ensure: 'present', name: '001 Test Rule', protocol: 'iptables', islastfrag: true } },
          error: 'Parameter `islastfrag` is specific to the `IPv6` protocol'
        },
        {
          # Covers `dst_type` and `src_type`
          valid: { is: {}, should: { ensure: 'present', name: '001 Test Rule', dst_type: ['! LOCAL', '! UNICAST'] } },
          invalid: { is: {}, should: { ensure: 'present', name: '001 Test Rule', dst_type: ['LOCAL', 'LOCAL'] } },
          error: '`dst_type` elements must be unique'
        },
        {
          valid: { is: {}, should: { ensure: 'present', name: '001 Test Rule', nflog_prefix: 'Test prefix' } },
          invalid: { is: {}, should: { ensure: 'present', name: '001 Test Rule', nflog_prefix: '12345678901234567890123456789012345678901234567890123456789012345' } },
          error: 'Parameter `nflog_prefix`` must be less than 64 characters'
        },
        {
          # Covers `dst_range` and `src_range`
          valid: { is: {}, should: { ensure: 'present', name: '001 Test Rule', protocol: 'IPv4', dst_range: '192.168.1.1-192.168.1.10' } },
          invalid: { is: {}, should: { ensure: 'present', name: '001 Test Rule', protocol: 'IPv4', dst_range: '5.10.64.0/24' } },
          error: 'The IP range must be in `IP1-IP2` format.'
        },
        {
          # Covers `dst_range` and `src_range`
          valid: { is: {}, should: { ensure: 'present', name: '001 Test Rule', protocol: 'IPv6', src_range: '1::46-2::48' } },
          invalid: { is: {}, should: { ensure: 'present', name: '001 Test Rule', protocol: 'IPv6', src_range: '1::46-248' } },
          error: 'Invalid IP address `248` in range `1::46-248`'
        },
      ].each do |validate|
        context "when validating: #{validate[:error]}" do
          it "valid Input: #{validate[:valid][:should]}" do
            expect { provider.validate_input(validate[:valid][:is], validate[:valid][:should]) }.not_to raise_error
          end

          it "invalid Input: #{validate[:invalid][:should]}" do
            expect { provider.validate_input(validate[:invalid][:is], validate[:invalid][:should]) }.to raise_error(ArgumentError, validate[:error])
          end
        end
      end
    end

    describe 'self.process_input(should)' do
      [
        {
          process: '`dport`, `sport` `state` `ctstate` and `ctstatus` arrays should only have the first value negated',
          should: { dport: ['! 54', '! 64', '! 74'] },
          result: { dport: ['! 54', '64', '74'] }
        },
        {
          process: '`jump` values should always be uppercase',
          should: { jump: 'accept' },
          result: { jump: 'ACCEPT' }
        },
        {
          process: '`source` and `destination` must be put through host_to_mask with protocol `IPv4`',
          should: { protocol: 'IPv4', source: '! 96.126.112.51', destination: '96.126.112.51' },
          result: { protocol: 'IPv4', source: '! 96.126.112.51/32', destination: '96.126.112.51/32' }
        },
        {
          process: '`source` and `destination` must be put through host_to_mask with protocol `IPv6`',
          should: { protocol: 'IPv6', source: '2001:db8:1234::', destination: '! 2001:db8:1234::' },
          result: { protocol: 'IPv6', source: '2001:db8:1234::/128', destination: '! 2001:db8:1234::/128' }
        },
        {
          process: '`ct` attributes must be put through a restricted host_to_mask with protocol `IPv4`',
          should: { protocol: 'IPv4', ctorigsrc: '96.126.112.51/32', ctorigdst: '! 96.126.112.51', ctreplsrc: '96.126.112.51/24', ctrepldst: '96.126.112.51/16' },
          result: { protocol: 'IPv4', ctorigsrc: '96.126.112.51', ctorigdst: '! 96.126.112.51', ctreplsrc: '96.126.112.0/24', ctrepldst: '96.126.0.0/16' }
        },
        {
          process: '`ct` attributes must be put through a restricted host_to_mask with protocol `IPv6`',
          should: { protocol: 'IPv6', ctorigsrc: '! 2001:db8:1234::', ctorigdst: '2001:db8:1234::/128', ctreplsrc: '2001:db8:1234::/32', ctrepldst: '2001:db8:1234::/16' },
          result: { protocol: 'IPv6', ctorigsrc: '! 2001:db8:1234::', ctorigdst: '2001:db8:1234::', ctreplsrc: '2001:db8::/32', ctrepldst: '2001::/16' }
        },
        {
          process: '`icmp` needs to be converted to a number if passed as a string with protocol `IPv4`',
          should: { protocol: 'IPv4', icmp: 'destination-unreachable' },
          result: { protocol: 'IPv4', icmp: '3' }
        },
        {
          process: '`icmp` needs to be converted to a number if passed as a string with protocol `IPv6`',
          should: { protocol: 'IPv6', icmp: 'destination-unreachable' },
          result: { protocol: 'IPv6', icmp: '1' }
        },
        {
          process: '`log_level` needs to be converted to a number if passed as a string',
          should: { log_level: 'alert' },
          result: { log_level: '1' }
        },
        {
          process: '`set_mark`, `match_mark` and `connmark` must be put through mark_mask_to_hex/mark_to_hex',
          should: { set_mark: '42', match_mark: '42', connmark: '42' },
          result: { set_mark: '0x2a/0xffffffff', match_mark: '0x2a', connmark: '0x2a' }
        },
        {
          process: '`time_start` and `time_stop` must be applied in full HH:MM:SS format',
          should: { time_start: '9:30', time_stop: '12:45' },
          result: { time_start: '09:30:00', time_stop: '12:45:00' }
        },
        {
          process: 'If `sport` or `dport` has been pass arange with `-` as the divider, replace it with `:`',
          should: { sport: '50-60', dport: ['50-60', '70-80'] },
          result: { sport: '50:60', dport: ['50:60', '70:80'] }
        },
      ].each do |process|
        it "Process: #{process[:process]}" do
          expect(provider.process_input(process[:should])).to eq(process[:result])
        end
      end
    end

    describe 'self.hash_to_rule(_context, _name, rule)' do
      [
        {
          logic_section: ':name, :string, :string_hex, :bytecode, :u32, :nflog_prefix, :log_prefix', rules: [
            { name: '001 test rule',
              hash: { name: '001 test rule' },
              result: " -m comment --comment '001 test rule'" },
            { name: '001 test rule',
              hash: { name: '001 test rule', string_hex: 'test' },
              result: " -m string --hex-string 'test' -m comment --comment '001 test rule'" },
            { name: '001 test rule',
              hash: { name: '001 test rule', string_hex: '! test' },
              result: " -m string ! --hex-string 'test' -m comment --comment '001 test rule'" },
          ]
        },
        {
          logic_section: ':sport, :dport', rules: [
            { name: '001 test rule',
              hash: { name: '001 test rule', sport: '50', dport: '! 60' },
              result: " --sport 50 ! --dport 60 -m comment --comment '001 test rule'" },
            { name: '001 test rule',
              hash: { name: '001 test rule', sport: '50:60', dport: '! 60:70' },
              result: " --sport 50:60 ! --dport 60:70 -m comment --comment '001 test rule'" },
            { name: '001 test rule',
              hash: { name: '001 test rule', sport: ['50', '60:70'], dport: ['! 80:90', '100'] },
              result: " -m multiport --sports 50,60:70 -m multiport ! --dports 80:90,100 -m comment --comment '001 test rule'" },
          ]
        },
        {
          logic_section: ':src_type, :dst_type, :ipset, :match_mark, :mss, :connmark', rules: [
            { name: '001 test rule',
              hash: { name: '001 test rule', src_type: 'LOCAL --limit-iface-in', dst_type: '! UNICAST' },
              result: " -m addrtype --src-type LOCAL --limit-iface-in -m addrtype ! --dst-type UNICAST -m comment --comment '001 test rule'" },
            { name: '001 test rule',
              hash: { name: '001 test rule', src_type: ['LOCAL', '! UNICAST'], dst_type: ['! UNICAST', 'LOCAL'] },
              result: " -m addrtype --src-type LOCAL -m addrtype ! --src-type UNICAST -m addrtype ! --dst-type UNICAST -m addrtype --dst-type LOCAL -m comment --comment '001 test rule'" },
          ]
        },
        {
          logic_section: ':state, :ctstate, :ctstatus, :month_days, :week_days', rules: [
            { name: '001 test rule',
              hash: { name: '001 test rule', state: 'INVALID', ctstate: '! INVALID', month_days: 22 },
              result: " -m state --state INVALID -m conntrack ! --ctstate INVALID -m time --monthdays 22 -m comment --comment '001 test rule'" },
            { name: '001 test rule',
              hash: { name: '001 test rule', state: ['INVALID', 'ESTABLISHED'], ctstate: ['! INVALID', 'ESTABLISHED'], month_days: [22, 24, 30] },
              result: " -m state --state INVALID,ESTABLISHED -m conntrack ! --ctstate INVALID,ESTABLISHED -m time --monthdays 22,24,30 -m comment --comment '001 test rule'" },
          ]
        },
        {
          logic_section: ':icmp', rules: [
            { name: '001 test rule',
              hash: { name: '001 test rule', protocol: 'IPv4', icmp: '3' },
              result: " -m icmp --icmp-type 3 -m comment --comment '001 test rule'" },
            { name: '001 test rule',
              hash: { name: '001 test rule', protocol: 'IPv6', icmp: '3' },
              result: " -m icmp6 --icmpv6-type 3 -m comment --comment '001 test rule'" },
            { name: '001 test rule',
              hash: { name: '001 test rule', protocol: 'IPv4', icmp: '! 3' },
              result: " -m icmp ! --icmp-type 3 -m comment --comment '001 test rule'" },
            { name: '001 test rule',
              hash: { name: '001 test rule', protocol: 'IPv6', icmp: '! 3' },
              result: " -m icmp6 ! --icmpv6-type 3 -m comment --comment '001 test rule'" },
          ]
        },
        {
          logic_section: ':recent', rules: [
            { name: '001 test rule',
              hash: { name: '001 test rule', recent: 'update' },
              result: " -m recent --update -m comment --comment '001 test rule'" },
            { name: '001 test rule',
              hash: { name: '001 test rule', recent: '! update' },
              result: " -m recent ! --update -m comment --comment '001 test rule'" },
          ]
        },
        {
          logic_section: ':rpfilter', rules: [
            { name: '001 test rule',
              hash: { name: '001 test rule', rpfilter: 'loose' },
              result: " -m rpfilter --loose -m comment --comment '001 test rule'" },
            { name: '001 test rule',
              hash: { name: '001 test rule', rpfilter: ['loose', 'validmark'] },
              result: " -m rpfilter --loose --validmark -m comment --comment '001 test rule'" },
          ]
        },
        {
          logic_section: ':proto, :source, :destination, :iniface, :outiface, :physdev_in, etc.', rules: [
            { name: '001 test rule',
              hash: { name: '001 test rule', proto: 'icmp', source: '192.168.2.0/24' },
              result: " -s 192.168.2.0/24 -p icmp -m comment --comment '001 test rule'" },
            { name: '001 test rule',
              hash: { name: '001 test rule', proto: '! icmp', source: '! 192.168.2.0/24' },
              result: " ! -s 192.168.2.0/24 ! -p icmp -m comment --comment '001 test rule'" },
          ]
        },
        {
          logic_section: 'Default (i.e.: stat_mode, stat_every, stat_packet, stat_probability, etc.)', rules: [
            { name: '001 test rule',
              hash: { name: '001 test rule', stat_mode: 'nth', stat_every: 5 },
              result: " -m statistic --mode nth --every 5 -m comment --comment '001 test rule'" },
          ]
        },
        {
          logic_section: 'Boolean (i.e. :checksum_fill, :clamp_mss_to_pmtu, :isfragment, etc)', rules: [
            { name: '001 test rule',
              hash: { name: '001 test rule', checksum_fill: true, random: true },
              result: " --checksum-fill --random -m comment --comment '001 test rule'" },
          ]
        },
        {
          logic_section: 'module_to_argument_mapping', rules: [
            { name: '001 test rule',
              hash: { name: '001 test rule', physdev_in: 'lo', physdev_out: '! lo', ipsec_dir: 'in', ipsec_policy: 'ipsec' },
              result: " -m physdev --physdev-in lo ! --physdev-out lo -m policy --dir in --pol ipsec -m comment --comment '001 test rule'" },
          ]
        },
      ].each do |test|
        context "with logic section: #{test[:logic_section]}" do
          test[:rules].each do |rule|
            it "parses hash: '#{rule[:hash]}'" do
              expect(provider.hash_to_rule(context, rule[:name], rule[:hash])).to eq(rule[:result])
            end
          end
        end
      end
    end

    describe 'self.insert_order(context, name, chain, table, protocol)' do
      let(:ipv4_rules) do
        [{ ensure: 'present', table: 'filter', protocol: 'IPv4', name: '9001 test rule', chain: 'INPUT' },
         { ensure: 'present', table: 'filter', protocol: 'IPv4', name: '002 test rule', chain: 'INPUT' },
         { ensure: 'present', table: 'filter', protocol: 'IPv4', name: '003 test rule', chain: 'INPUT' },
         { ensure: 'present', table: 'filter', protocol: 'IPv4', name: '9002 test rule', chain: 'INPUT' },
         { ensure: 'present', table: 'filter', protocol: 'IPv4', name: '9003 test rule', chain: 'INPUT' },
         { ensure: 'present', table: 'filter', protocol: 'IPv4', name: '005 test rule', chain: 'INPUT' },
         { ensure: 'present', table: 'filter', protocol: 'IPv4', name: '006 test rule', chain: 'OUTPUT' },
         { ensure: 'present', table: 'raw', protocol: 'IPv4', name: '007 test rule', chain: 'OUTPUT' },
         { ensure: 'present', table: 'raw', protocol: 'IPv4', name: '008 test rule', chain: 'OUTPUT' }]
      end
      let(:ipv6_rules) do
        [{ ensure: 'present', table: 'filter', protocol: 'IPv6', name: '010 test rule', chain: 'INPUT' },
         { ensure: 'present', table: 'filter', protocol: 'IPv6', name: '012 test rule', chain: 'INPUT' },
         { ensure: 'present', table: 'raw', protocol: 'IPv6', name: '013 test rule', chain: 'OUTPUT' },
         { ensure: 'present', table: 'raw', protocol: 'IPv6', name: '015 test rule', chain: 'OUTPUT' }]
      end

      [
        { name: '001 test rule', chain: 'INPUT', table: 'filter', protocol: 'IPv4', result: 1 },
        { name: '002 test rule', chain: 'INPUT', table: 'filter', protocol: 'IPv4', result: 2 },
        { name: '004 test rule', chain: 'INPUT', table: 'filter', protocol: 'IPv4', result: 4 },
        { name: '005 test rule', chain: 'OUTPUT', table: 'filter', protocol: 'IPv4', result: 1 },
        { name: '007 test rule', chain: 'OUTPUT', table: 'raw', protocol: 'IPv4', result: 1 },
        { name: '009 test rule', chain: 'OUTPUT', table: 'raw', protocol: 'IPv4', result: 3 },
        { name: '011 test rule', chain: 'INPUT', table: 'filter', protocol: 'IPv6', result: 2 },
        { name: '016 test rule', chain: 'OUTPUT', table: 'raw', protocol: 'IPv6', result: 3 },
        { name: '017 test rule', chain: 'FORWARD', table: 'filter', protocol: 'IPv4', result: 1 },
      ].each do |rule|
        it do
          allow(described_class).to receive(:get_rules).with(context, true, ['IPv4']).and_return(ipv4_rules)
          allow(described_class).to receive(:get_rules).with(context, true, ['IPv6']).and_return(ipv6_rules)

          expect(provider.insert_order(context, rule[:name], rule[:chain], rule[:table], rule[:protocol])).to eq(rule[:result])
        end
      end
    end
  end
end
