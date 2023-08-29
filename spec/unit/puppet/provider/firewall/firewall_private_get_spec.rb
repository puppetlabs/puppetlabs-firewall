# frozen_string_literal: true

require 'spec_helper'
require 'puppet/resource_api'

ensure_module_defined('Puppet::Provider::Firewall')
require 'puppet/provider/firewall/firewall'

RSpec.describe Puppet::Provider::Firewall::Firewall do
  describe 'Private Methods - Get' do
    subject(:provider) { described_class }

    let(:type) { Puppet::Type.type('firewall') }
    let(:context) { Puppet::ResourceApi::BaseContext.new(type.type_definition.definition) }

    # describe "self.get_rules(context, basic, protocols = ['IPv4', 'IPv6'])" do
    # No tests written as method is mainly a wrapper and contains little to no actual logic.
    # end

    describe 'self.rule_to_name(_context, rule, table_name, protocol)' do
      [
        {
          rule: '-A INPUT -p tcp -m comment --comment "001 test rule"',
          table_name: 'filter', protocol: 'IPv4',
          result: { ensure: 'present', table: 'filter', protocol: 'IPv4', name: '001 test rule', chain: 'INPUT' }
        },
        {
          rule: '-A OUTPUT -p tcp -m comment --comment "002 test rule"',
          table_name: 'raw', protocol: 'IPv6',
          result: { ensure: 'present', table: 'raw', protocol: 'IPv6', name: '002 test rule', chain: 'OUTPUT' }
        },
      ].each do |test|
        it "parses the rule: '#{test[:rule]}'" do
          expect(provider.rule_to_name(context, test[:rule], test[:table_name], test[:protocol])).to eq(test[:result])
        end
      end
    end

    describe 'self.rule_to_hash(_context, rule, table_name, protocol)' do
      # Since the boolean values are returned at all times, we keep them as a seperate hash and then merge the situational
      # expected results into them, overwriting these ones if needed.
      let(:boolean_block) do
        {
          checksum_fill: false, clamp_mss_to_pmtu: false, isfragment: false, ishasmorefrags: false, islastfrag: false,
          isfirstfrag: false, log_uid: false, log_tcp_sequence: false, log_tcp_options: false, log_ip_options: false,
          random_fully: false, random: false, rdest: false, reap: false, rsource: false, rttl: false, socket: false,
          physdev_is_bridged: false, physdev_is_in: false, physdev_is_out: false, time_contiguous: false,
          kernel_timezone: false, clusterip_new: false, queue_bypass: false, ipvs: false, notrack: false
        }
      end

      [
        {
          logic_section: ':name, :string, :string_hex, :bytecode, :u32, :nflog_prefix, :log_prefix', rules: [
            { rule: '-A INPUT -p tcp -m comment --comment "001 test rule"',
              table_name: 'filter', protocol: 'IPv4',
              result: {
                line: '-A INPUT -p tcp -m comment --comment "001 test rule"',
                ensure: 'present', table: 'filter', protocol: 'IPv4', name: '001 test rule', chain: 'INPUT', proto: 'tcp'
              } },
            { rule: '-A INPUT -p tcp -m comment --comment "001 test rule" --string test_string',
              table_name: 'filter', protocol: 'IPv4',
              result: {
                line: '-A INPUT -p tcp -m comment --comment "001 test rule" --string test_string',
                ensure: 'present', table: 'filter', protocol: 'IPv4', name: '001 test rule', chain: 'INPUT', proto: 'tcp',
                string: 'test_string'
              } },
            { rule: '-A INPUT -p tcp -m comment --comment "001 test rule" ! --string test_string',
              table_name: 'filter', protocol: 'IPv4',
              result: {
                line: '-A INPUT -p tcp -m comment --comment "001 test rule" ! --string test_string',
                ensure: 'present', table: 'filter', protocol: 'IPv4', name: '001 test rule', chain: 'INPUT', proto: 'tcp',
                string: '! test_string'
              } },
            { rule: '-A INPUT -p tcp -m comment --comment "001 test rule" ! --string "test string"',
              table_name: 'filter', protocol: 'IPv4',
              result: {
                line: '-A INPUT -p tcp -m comment --comment "001 test rule" ! --string "test string"',
                ensure: 'present', table: 'filter', protocol: 'IPv4', name: '001 test rule', chain: 'INPUT', proto: 'tcp',
                string: '! test string'
              } },
          ]
        },
        {
          logic_section: ':sport, :dport', rules: [
            { rule: '-A INPUT -p tcp -m comment --comment "001 test rule" --dport 20',
              table_name: 'filter', protocol: 'IPv4',
              result: {
                line: '-A INPUT -p tcp -m comment --comment "001 test rule" --dport 20',
                ensure: 'present', table: 'filter', protocol: 'IPv4', name: '001 test rule', chain: 'INPUT', proto: 'tcp',
                dport: '20'
              } },
            { rule: '-A INPUT -p tcp -m comment --comment "001 test rule" --dport 20:30',
              table_name: 'filter', protocol: 'IPv4',
              result: {
                line: '-A INPUT -p tcp -m comment --comment "001 test rule" --dport 20:30',
                ensure: 'present', table: 'filter', protocol: 'IPv4', name: '001 test rule', chain: 'INPUT', proto: 'tcp',
                dport: '20:30'
              } },
            { rule: '-A INPUT -p tcp -m comment --comment "001 test rule" ! --dport 20',
              table_name: 'filter', protocol: 'IPv4',
              result: {
                line: '-A INPUT -p tcp -m comment --comment "001 test rule" ! --dport 20',
                ensure: 'present', table: 'filter', protocol: 'IPv4', name: '001 test rule', chain: 'INPUT', proto: 'tcp',
                dport: '! 20'
              } },
            { rule: '-A INPUT -p tcp -m comment --comment "001 test rule" -m multiport --dports 20,30,40:50',
              table_name: 'filter', protocol: 'IPv4',
              result: {
                line: '-A INPUT -p tcp -m comment --comment "001 test rule" -m multiport --dports 20,30,40:50',
                ensure: 'present', table: 'filter', protocol: 'IPv4', name: '001 test rule', chain: 'INPUT', proto: 'tcp',
                dport: ['20', '30', '40:50']
              } },
            { rule: '-A INPUT -p tcp -m comment --comment "001 test rule" -m multiport ! --dports 20,30,40:50',
              table_name: 'filter', protocol: 'IPv4',
              result: {
                line: '-A INPUT -p tcp -m comment --comment "001 test rule" -m multiport ! --dports 20,30,40:50',
                ensure: 'present', table: 'filter', protocol: 'IPv4', name: '001 test rule', chain: 'INPUT', proto: 'tcp',
                dport: ['! 20', '30', '40:50']
              } },
          ]
        },
        {
          logic_section: ':tcp_flags', rules: [
            { rule: '-A INPUT -p tcp -m comment --comment "001 test rule" --tcp-flags FIN,SYN,RST FIN',
              table_name: 'filter', protocol: 'IPv4',
              result: {
                line: '-A INPUT -p tcp -m comment --comment "001 test rule" --tcp-flags FIN,SYN,RST FIN',
                ensure: 'present', table: 'filter', protocol: 'IPv4', name: '001 test rule', chain: 'INPUT', proto: 'tcp',
                tcp_flags: 'FIN,SYN,RST FIN'
              } },
            { rule: '-A INPUT -p tcp -m comment --comment "001 test rule" ! --tcp-flags FIN,SYN,RST FIN',
              table_name: 'filter', protocol: 'IPv4',
              result: {
                line: '-A INPUT -p tcp -m comment --comment "001 test rule" ! --tcp-flags FIN,SYN,RST FIN',
                ensure: 'present', table: 'filter', protocol: 'IPv4', name: '001 test rule', chain: 'INPUT', proto: 'tcp',
                tcp_flags: '! FIN,SYN,RST FIN'
              } },
          ]
        },
        {
          logic_section: ':src_type, :dst_type, :ipset, :match_mark, :mss, :connmark', rules: [
            { rule: '-A INPUT -p tcp -m comment --comment "001 test rule" -m addrtype --src-type LOCAL',
              table_name: 'filter', protocol: 'IPv4',
              result: {
                line: '-A INPUT -p tcp -m comment --comment "001 test rule" -m addrtype --src-type LOCAL',
                ensure: 'present', table: 'filter', protocol: 'IPv4', name: '001 test rule', chain: 'INPUT', proto: 'tcp',
                src_type: 'LOCAL'
              } },
            { rule: '-A INPUT -p tcp -m comment --comment "001 test rule" -m addrtype --src-type LOCAL --limit-iface-in -m addrtype ! --src-type UNICAST',
              table_name: 'filter', protocol: 'IPv4',
              result: {
                line: '-A INPUT -p tcp -m comment --comment "001 test rule" -m addrtype --src-type LOCAL --limit-iface-in -m addrtype ! --src-type UNICAST',
                ensure: 'present', table: 'filter', protocol: 'IPv4', name: '001 test rule', chain: 'INPUT', proto: 'tcp',
                src_type: ['LOCAL --limit-iface-in', '! UNICAST']
              } },
            { rule: '-A INPUT -p tcp -m comment --comment "001 test rule" -m set --match-set denylist src,dst',
              table_name: 'filter', protocol: 'IPv4',
              result: {
                line: '-A INPUT -p tcp -m comment --comment "001 test rule" -m set --match-set denylist src,dst',
                ensure: 'present', table: 'filter', protocol: 'IPv4', name: '001 test rule', chain: 'INPUT', proto: 'tcp',
                ipset: 'denylist src,dst'
              } },
            { rule: '-A INPUT -p tcp -m comment --comment "001 test rule" -m set --match-set denylist dst -m set ! --match-set denylist2 src,dst',
              table_name: 'filter', protocol: 'IPv4',
              result: {
                line: '-A INPUT -p tcp -m comment --comment "001 test rule" -m set --match-set denylist dst -m set ! --match-set denylist2 src,dst',
                ensure: 'present', table: 'filter', protocol: 'IPv4', name: '001 test rule', chain: 'INPUT', proto: 'tcp',
                ipset: ['denylist dst', '! denylist2 src,dst']
              } },
            { rule: '-A INPUT -p tcp -m comment --comment "001 test rule" -m mark --mark 0x1',
              table_name: 'filter', protocol: 'IPv4',
              result: {
                line: '-A INPUT -p tcp -m comment --comment "001 test rule" -m mark --mark 0x1',
                ensure: 'present', table: 'filter', protocol: 'IPv4', name: '001 test rule', chain: 'INPUT', proto: 'tcp',
                match_mark: '0x1'
              } },
            { rule: '-A INPUT -p tcp -m comment --comment "001 test rule" -m mark --mark 0x32 -m mark ! --mark 0x1',
              table_name: 'filter', protocol: 'IPv4',
              result: {
                line: '-A INPUT -p tcp -m comment --comment "001 test rule" -m mark --mark 0x32 -m mark ! --mark 0x1',
                ensure: 'present', table: 'filter', protocol: 'IPv4', name: '001 test rule', chain: 'INPUT', proto: 'tcp',
                match_mark: ['0x32', '! 0x1']
              } },
          ]
        },
        {
          logic_section: ':state, :ctstate, :ctstatus, :month_days, :week_days', rules: [
            { rule: '-A INPUT -p tcp -m comment --comment "001 test rule" -state --state INVALID',
              table_name: 'filter', protocol: 'IPv4',
              result: {
                line: '-A INPUT -p tcp -m comment --comment "001 test rule" -state --state INVALID',
                ensure: 'present', table: 'filter', protocol: 'IPv4', name: '001 test rule', chain: 'INPUT', proto: 'tcp',
                state: 'INVALID'
              } },
            { rule: '-A INPUT -p tcp -m comment --comment "001 test rule" -state ! --state INVALID',
              table_name: 'filter', protocol: 'IPv4',
              result: {
                line: '-A INPUT -p tcp -m comment --comment "001 test rule" -state ! --state INVALID',
                ensure: 'present', table: 'filter', protocol: 'IPv4', name: '001 test rule', chain: 'INPUT', proto: 'tcp',
                state: '! INVALID'
              } },
            { rule: '-A INPUT -p tcp -m comment --comment "001 test rule" -state ! --state INVALID,NEW',
              table_name: 'filter', protocol: 'IPv4',
              result: {
                line: '-A INPUT -p tcp -m comment --comment "001 test rule" -state ! --state INVALID,NEW',
                ensure: 'present', table: 'filter', protocol: 'IPv4', name: '001 test rule', chain: 'INPUT', proto: 'tcp',
                state: ['! INVALID', 'NEW']
              } },
            { rule: '-A INPUT -p tcp -m comment --comment "001 test rule" --monthdays 26,28',
              table_name: 'filter', protocol: 'IPv4',
              result: {
                line: '-A INPUT -p tcp -m comment --comment "001 test rule" --monthdays 26,28',
                ensure: 'present', table: 'filter', protocol: 'IPv4', name: '001 test rule', chain: 'INPUT', proto: 'tcp',
                month_days: [26, 28]
              } },
          ]
        },
        {
          logic_section: ':icmp', rules: [
            { rule: '-A INPUT -p tcp -m comment --comment "001 test rule" -m icmp --icmp-type 0',
              table_name: 'filter', protocol: 'IPv4',
              result: {
                line: '-A INPUT -p tcp -m comment --comment "001 test rule" -m icmp --icmp-type 0',
                ensure: 'present', table: 'filter', protocol: 'IPv4', name: '001 test rule', chain: 'INPUT', proto: 'tcp',
                icmp: '0'
              } },
            { rule: '-A INPUT -p tcp -m comment --comment "001 test rule" -m icmp6 --icmpv6-type 129',
              table_name: 'filter', protocol: 'IPv6',
              result: {
                line: '-A INPUT -p tcp -m comment --comment "001 test rule" -m icmp6 --icmpv6-type 129',
                ensure: 'present', table: 'filter', protocol: 'IPv6', name: '001 test rule', chain: 'INPUT', proto: 'tcp',
                icmp: '129'
              } },
          ]
        },
        {
          logic_section: ':recent', rules: [
            { rule: '-A INPUT -p tcp -m comment --comment "001 test rule" -m recent --set',
              table_name: 'filter', protocol: 'IPv4',
              result: {
                line: '-A INPUT -p tcp -m comment --comment "001 test rule" -m recent --set',
                ensure: 'present', table: 'filter', protocol: 'IPv4', name: '001 test rule', chain: 'INPUT', proto: 'tcp',
                recent: 'set'
              } },
            { rule: '-A INPUT -p tcp -m comment --comment "001 test rule" -m recent ! --set',
              table_name: 'filter', protocol: 'IPv4',
              result: {
                line: '-A INPUT -p tcp -m comment --comment "001 test rule" -m recent ! --set',
                ensure: 'present', table: 'filter', protocol: 'IPv4', name: '001 test rule', chain: 'INPUT', proto: 'tcp',
                recent: '! set'
              } },
          ]
        },
        {
          logic_section: ':rpfilter', rules: [
            { rule: '-A INPUT -p tcp -m comment --comment "001 test rule" -m rpfilter --loose',
              table_name: 'filter', protocol: 'IPv4',
              result: {
                line: '-A INPUT -p tcp -m comment --comment "001 test rule" -m rpfilter --loose',
                ensure: 'present', table: 'filter', protocol: 'IPv4', name: '001 test rule', chain: 'INPUT', proto: 'tcp',
                rpfilter: 'loose'
              } },
            { rule: '-A INPUT -p tcp -m comment --comment "001 test rule" -m rpfilter --loose -m rpfilter --accept-local',
              table_name: 'filter', protocol: 'IPv4',
              result: {
                line: '-A INPUT -p tcp -m comment --comment "001 test rule" -m rpfilter --loose -m rpfilter --accept-local',
                ensure: 'present', table: 'filter', protocol: 'IPv4', name: '001 test rule', chain: 'INPUT', proto: 'tcp',
                rpfilter: ['loose', 'accept-local']
              } },
          ]
        },
        {
          logic_section: ':proto, :source, :destination, :iniface, :outiface, etc.', rules: [
            { rule: '-A INPUT -p tcp -m comment --comment "001 test rule" -s 192.168.2.0/24',
              table_name: 'filter', protocol: 'IPv4',
              result: {
                line: '-A INPUT -p tcp -m comment --comment "001 test rule" -s 192.168.2.0/24',
                ensure: 'present', table: 'filter', protocol: 'IPv4', name: '001 test rule', chain: 'INPUT', proto: 'tcp',
                source: '192.168.2.0/24'
              } },
            { rule: '-A INPUT -p tcp -m comment --comment "001 test rule" ! -s 192.168.2.0/24',
              table_name: 'filter', protocol: 'IPv4',
              result: {
                line: '-A INPUT -p tcp -m comment --comment "001 test rule" ! -s 192.168.2.0/24',
                ensure: 'present', table: 'filter', protocol: 'IPv4', name: '001 test rule', chain: 'INPUT', proto: 'tcp',
                source: '! 192.168.2.0/24'
              } },
          ]
        },
        {
          logic_section: 'Default (i.e. :chain, stat_mode, stat_every, stat_packet, etc.)', rules: [
            { rule: '-A INPUT -p tcp -m comment --comment "001 test rule" -m statistic --mode nth',
              table_name: 'filter', protocol: 'IPv4',
              result: {
                line: '-A INPUT -p tcp -m comment --comment "001 test rule" -m statistic --mode nth',
                ensure: 'present', table: 'filter', protocol: 'IPv4', name: '001 test rule', chain: 'INPUT', proto: 'tcp',
                stat_mode: 'nth'
              } },
          ]
        },
        {
          logic_section: 'Boolean (i.e. :checksum_fill, :clamp_mss_to_pmtu, :isfragment, etc)', rules: [
            { rule: '-A INPUT -p tcp -m comment --comment "001 test rule" --checksum-fill',
              table_name: 'filter', protocol: 'IPv4',
              result: {
                line: '-A INPUT -p tcp -m comment --comment "001 test rule" --checksum-fill',
                ensure: 'present', table: 'filter', protocol: 'IPv4', name: '001 test rule', chain: 'INPUT', proto: 'tcp',
                checksum_fill: true
              } },
            { rule: '-A INPUT -p tcp -m comment --comment "001 test rule" --checksum-fill -m socket',
              table_name: 'filter', protocol: 'IPv4',
              result: {
                line: '-A INPUT -p tcp -m comment --comment "001 test rule" --checksum-fill -m socket',
                ensure: 'present', table: 'filter', protocol: 'IPv4', name: '001 test rule', chain: 'INPUT', proto: 'tcp',
                checksum_fill: true, socket: true
              } },
          ]
        },
        {
          logic_section: 'non-complex flags (i.e. :isfragment = `-f`)', rules: [
            { rule: '-A INPUT -p tcp -m comment --comment "001 test rule" -f --tcp-flags FIN,SYN,RST,ACK SYN',
              table_name: 'filter', protocol: 'IPv4',
              result: {
                line: '-A INPUT -p tcp -m comment --comment "001 test rule" -f --tcp-flags FIN,SYN,RST,ACK SYN',
                ensure: 'present', table: 'filter', protocol: 'IPv4', name: '001 test rule', chain: 'INPUT', proto: 'tcp',
                isfragment: true, tcp_flags: 'FIN,SYN,RST,ACK SYN'
              } },
          ]
        },
      ].each do |test|
        context "with logic section: #{test[:logic_section]}" do
          test[:rules].each do |rule|
            it "parses the rule: '#{rule[:rule]}'" do
              # `.sort` added to each value for conveniance sake
              expect(provider.rule_to_hash(context, rule[:rule], rule[:table_name], rule[:protocol]).sort)
                .to eq(boolean_block.merge(rule[:result]).sort)
            end
          end
        end
      end
    end

    describe 'self.validate_get(_context, rules)' do
      [
        {
          input: [{ name: '001 test rule' }, { name: '001 test rule' }],
          error: 'Duplicate names have been found within your Firewalls. This prevents the module from working correctly and must be manually resolved.'
        },
      ].each do |validate|
        it "Validate: #{validate[:error]}" do
          expect { provider.validate_get(context, validate[:input]) }.to raise_error(ArgumentError, validate[:error])
        end
      end
    end

    describe 'self.process_get(_context, rule_hash, rule, counter)' do
      [
        {
          process: 'if no `name` is returned, generate one',
          rule_hash: { ensure: 'present', table: 'filter', protocol: 'IPv4', chain: 'INPUT', proto: 'tcp' },
          rule: 'A INPUT -p tcp',
          counter: 1,
          result: { ensure: 'present', table: 'filter', protocol: 'IPv4', chain: 'INPUT', proto: 'tcp',
                    name: '9001 9115c4f4e9a27e6519767ade2f6aa22a66268cea6bf3fb739c6963cdbadcf682' }
        },
        {
          process: 'if returned `name` has no number, assign one',
          rule_hash: { ensure: 'present', table: 'filter', protocol: 'IPv4', chain: 'INPUT', proto: 'tcp', name: 'test rule' },
          rule: 'A INPUT -p tcp -m comment --comment "test rule"',
          counter: 2,
          result: { ensure: 'present', table: 'filter', protocol: 'IPv4', chain: 'INPUT', proto: 'tcp',
                    name: '9002 test rule' }
        },
        {
          process: 'if no `proto` is returned, assume it is `all`',
          rule_hash: { ensure: 'present', table: 'filter', protocol: 'IPv4', chain: 'INPUT', name: '001 test rule' },
          rule: 'A INPUT -m comment --comment "001 test rule"',
          counter: 0,
          result: { ensure: 'present', table: 'filter', protocol: 'IPv4', chain: 'INPUT', proto: 'all', name: '001 test rule' }
        },
        {
          process: 'if `proto` is returned as number, convert to name',
          rule_hash: { ensure: 'present', table: 'filter', protocol: 'IPv4', chain: 'INPUT', proto: '1', name: '001 test rule' },
          rule: 'A INPUT -p 1 -m comment --comment "001 test rule"',
          counter: 0,
          result: { ensure: 'present', table: 'filter', protocol: 'IPv4', chain: 'INPUT', proto: 'icmp', name: '001 test rule' }
        },
        {
          process: "if `set_dscp` is returned, also return it's valid class name `set_dscp_class`",
          rule_hash: { ensure: 'present', table: 'filter', protocol: 'IPv4', chain: 'INPUT', proto: 'tcp',
                       name: '001 test rule', set_dscp: '0x0c' },
          rule: 'A INPUT -p tcp -m comment --comment "001 test rule" --set-dscp 0x0c',
          counter: 0,
          result: { ensure: 'present', table: 'filter', protocol: 'IPv4', chain: 'INPUT', proto: 'tcp',
                    name: '001 test rule', set_dscp: '0x0c', set_dscp_class: 'af12' }
        },
      ].each do |process|
        it "Process: #{process[:process]}" do
          expect(provider.process_get(context, process[:rule_hash], process[:rule], process[:counter])).to eq(process[:result])
        end
      end
    end

    describe 'self.create_absent(namevar, title)' do
      [
        { namevar: :name, title: '001 test rule', result: { ensure: 'absent', name: '001 test rule' } },
      ].each do |create|
        it "Create: #{create}" do
          expect(provider.create_absent(create[:namevar], create[:title])).to eq(create[:result])
        end
      end
    end
  end
end
