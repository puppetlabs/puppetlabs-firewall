# frozen_string_literal: true

require 'spec_helper'
require 'puppet/resource_api'

ensure_module_defined('Puppet::Provider::Firewall')
require 'puppet/provider/firewall/firewall'

RSpec.describe Puppet::Provider::Firewall::Firewall do
  describe 'Public Methods' do
    subject(:provider) { described_class.new }

    let(:type) { Puppet::Type.type('firewall') }
    let(:context) { Puppet::ResourceApi::BaseContext.new(type.type_definition.definition) }

    # describe 'get(_context)' do
    #  This method is not tested as it simply serves as a wrapper for self.get_rules and self.validate_get and contains no actual logic.
    # end

    # describe 'set(context, changes)' do
    #  This method is not tested as it simply serves as a wrapper with little to no actual logic.
    # end

    describe 'create(context, name, should)' do
      [
        {
          should: { name: '001 IPv4 Test Rule', chain: 'INPUT', table: 'filter', protocol: 'IPv4', ensure: 'present' },
          arguments: '-m comment --comment "001 Test Rule"',
          create_command: 'iptables -t filter -I INPUT 1 -m comment --comment "001 Test Rule"'
        },
        {
          should: { name: '002 IPv6 Test Rule', chain: 'OUTPUT', table: 'raw', protocol: 'IPv6', ensure: 'present' },
          arguments: '-m comment --comment "002 Test Rule"',
          create_command: 'ip6tables -t raw -I OUTPUT 1 -m comment --comment "002 Test Rule"'
        },
      ].each do |test|
        it "creates the resource: '#{test[:should][:name]}'" do
          expect(context).to receive(:notice).with(%r{\ACreating Rule '#{test[:should][:name]}'})
          allow(described_class).to receive(:insert_order)
            .with(context, test[:should][:name], test[:should][:chain], test[:should][:table], test[:should][:protocol]).and_return(1)
          allow(described_class).to receive(:hash_to_rule)
            .with(context, test[:should][:name], test[:should]).and_return(test[:arguments])
          expect(Puppet::Util::Execution).to receive(:execute).with(test[:create_command])
          allow(PuppetX::Firewall::Utility).to receive(:persist_iptables).with(context, test[:should][:name], test[:should][:protocol])

          provider.create(context, test[:should][:name], test[:should])
        end
      end
    end

    describe 'update(context, name, should, is)' do
      [
        {
          should: { name: '001 IPv4 Test Rule', chain: 'INPUT', table: 'filter', protocol: 'IPv4', ensure: 'present' },
          arguments: '-m comment --comment "001 Test Rule"',
          update_command: 'iptables -t filter -R INPUT 1 -m comment --comment "001 Test Rule"'
        },
        {
          should: { name: '002 IPv6 Test Rule', chain: 'OUTPUT', table: 'raw', protocol: 'IPv6', ensure: 'present' },
          arguments: '-m comment --comment "002 Test Rule"',
          update_command: 'ip6tables -t raw -R OUTPUT 1 -m comment --comment "002 Test Rule"'
        },
      ].each do |test|
        it "updates the resource: '#{test[:should][:name]}'" do
          expect(context).to receive(:notice).with(%r{\Updating Rule '#{test[:should][:name]}'})
          allow(described_class).to receive(:insert_order)
            .with(context, test[:should][:name], test[:should][:chain], test[:should][:table], test[:should][:protocol]).and_return(1)
          allow(described_class).to receive(:hash_to_rule)
            .with(context, test[:should][:name], test[:should]).and_return(test[:arguments])
          expect(Puppet::Util::Execution).to receive(:execute).with(test[:update_command])
          allow(PuppetX::Firewall::Utility).to receive(:persist_iptables).with(context, test[:should][:name], test[:should][:protocol])

          provider.update(context, test[:should][:name], test[:should])
        end
      end
    end

    describe 'delete(context, name, is)' do
      [
        {
          is: {
            name: '001 IPv4 Test Rule', chain: 'INPUT', table: 'filter', protocol: 'IPv4', ensure: 'present',
            line: '-A INPUT 1 -m comment --comment "001 Test Rule"'
          },
          delete_command: 'iptables -t filter -D INPUT 1 -m comment --comment "001 Test Rule"'
        },
        {
          is: {
            name: '002 IPv6 Test Rule', chain: 'OUTPUT', table: 'raw', protocol: 'IPv6', ensure: 'present',
            line: '-A OUTPUT 1 -m comment --comment "002 Test Rule"'
          },
          delete_command: 'ip6tables -t raw -D OUTPUT 1 -m comment --comment "002 Test Rule"'
        },
      ].each do |test|
        it "deletes the resource: '#{test[:is][:name]}'" do
          allow(context).to receive(:notice).with(%r{\ADeleting Rule '#{test[:is][:name]}'})
          allow(described_class).to receive(:insert_order)
            .with(context, test[:is][:name], test[:is][:chain], test[:is][:table], test[:is][:protocol]).and_return(1)
          expect(Puppet::Util::Execution).to receive(:execute).with(test[:delete_command])
          allow(PuppetX::Firewall::Utility).to receive(:persist_iptables).with(context, test[:is][:name], test[:is][:protocol])

          provider.delete(context, test[:is][:name], test[:is])
        end
      end
    end

    describe 'insync?(context, _name, property_name, _is_hash, _should_hash)' do
      [
        { testing: 'protocol', property_name: :protocol, comparisons: [
          { is_hash: { protocol: 'IPv4' }, should_hash: { protocol: 'IPv4' }, result: true },
          { is_hash: { protocol: 'IPv4' }, should_hash: { protocol: 'iptables' }, result: true },
          { is_hash: { protocol: 'IPv4' }, should_hash: { protocol: 'ip6tables' }, result: false },
          { is_hash: { protocol: 'IPv6' }, should_hash: { protocol: 'IPv6' }, result: true },
          { is_hash: { protocol: 'IPv6' }, should_hash: { protocol: 'ip6tables' }, result: true },
          { is_hash: { protocol: 'IPv6' }, should_hash: { protocol: 'iptables' }, result: false },
        ] },
        { testing: 'source/destination', property_name: :source, comparisons: [
          { is_hash: { source: '10.1.5.28/32' }, should_hash: { protocol: 'IPv4', source: '10.1.5.28/32' }, result: true },
          { is_hash: { source: '10.1.5.28/32' }, should_hash: { protocol: 'IPv4', source: '10.1.5.28' }, result: true },
          { is_hash: { source: '10.1.5.28/32' }, should_hash: { protocol: 'iptables', source: '10.1.5.28' }, result: true },
          { is_hash: { source: '10.1.5.28/32' }, should_hash: { protocol: 'iptables', source: '10.1.5.27' }, result: false },
          { is_hash: { source: '1::49/128' }, should_hash: { protocol: 'IPv6', source: '1::49/128' }, result: true },
          { is_hash: { source: '1::49/128' }, should_hash: { protocol: 'IPv6', source: '1::49' }, result: true },
          { is_hash: { source: '1::49/128' }, should_hash: { protocol: 'ip6tables', source: '1::49' }, result: true },
          { is_hash: { source: '1::49/128' }, should_hash: { protocol: 'ip6tables', source: '1::50' }, result: false },
        ] },
        { testing: 'tcp_option/ct_proto/hop_limit', property_name: :tcp_option, comparisons: [
          { is_hash: { tcp_option: '6' }, should_hash: { tcp_option: 6 }, result: true },
          { is_hash: { tcp_option: '6' }, should_hash: { tcp_option: '6' }, result: true },
          { is_hash: { tcp_option: '5' }, should_hash: { tcp_option: '6' }, result: false },
        ] },
        { testing: 'tcp_flags', property_name: :tcp_flags, comparisons: [
          { is_hash: { tcp_flags: 'FIN SYN' }, should_hash: { tcp_flags: 'FIN SYN' }, result: true },
          { is_hash: { tcp_flags: 'FIN,SYN,RST,PSH,ACK,URG FIN,SYN,RST,PSH,ACK,URG' }, should_hash: { tcp_flags: 'ALL ALL' }, result: true },
          { is_hash: { tcp_flags: 'ALL FIN,SYN,RST,PSH,ACK,URG' }, should_hash: { tcp_flags: 'FIN,SYN,RST,PSH,ACK,URG ALL' }, result: true },
          { is_hash: { tcp_flags: 'ALL ALL' }, should_hash: { tcp_flags: 'FIN,SYN,RST,PSH,ACK,URG FIN,SYN,RST,PSH,ACK,URG' }, result: true },
          { is_hash: { tcp_flags: 'FIN SYN' }, should_hash: { tcp_flags: 'SYN FIN' }, result: false },
        ] },
        { testing: 'uid/gid', property_name: :uid, comparisons: [
          { is_hash: { uid: '0' }, should_hash: { uid: 'root' }, result: true },
          { is_hash: { uid: 'root' }, should_hash: { uid: '0' }, result: true },
          { is_hash: { uid: '0' }, should_hash: { uid: '0' }, result: true },
          { is_hash: { uid: 'root' }, should_hash: { uid: 'root' }, result: true },
          { is_hash: { uid: '1' }, should_hash: { uid: 'root' }, result: false },
        ] },
        { testing: 'mac_source', property_name: :mac_source, comparisons: [
          { is_hash: { mac_source: '0A:1B:3C:4D:5E:6F' }, should_hash: { mac_source: '0a:1b:3c:4d:5e:6f' }, result: true },
          { is_hash: { mac_source: '0a:1b:3c:4d:5e:6f' }, should_hash: { mac_source: '0A:1B:3C:4D:5E:6F' }, result: true },
          { is_hash: { mac_source: '0a:1b:3c:4d:5e:6f' }, should_hash: { mac_source: '0a:1b:3c:4d:5e:6f' }, result: true },
          { is_hash: { mac_source: '! 0A:1B:3C:4D:5E:6F' }, should_hash: { mac_source: '! 0A:1B:3C:4D:5E:6F' }, result: true },
          { is_hash: { mac_source: '! 0A:1B:3C:4D:5E:6F' }, should_hash: { mac_source: '0A:1B:3C:4D:5E:6F' }, result: false },
        ] },
        { testing: 'state/ctstate/ctstatus', property_name: :state, comparisons: [
          { is_hash: { state: 'NEW' }, should_hash: { state: 'NEW' }, result: nil },
          { is_hash: { state: ['NEW'] }, should_hash: { state: 'NEW' }, result: nil },
          { is_hash: { state: 'NEW' }, should_hash: { state: ['NEW', 'INVALID'] }, result: nil },
          { is_hash: { state: ['INVALID', 'NEW'] }, should_hash: { state: ['NEW', 'INVALID'] }, result: true },
          { is_hash: { state: ['! INVALID', 'NEW'] }, should_hash: { state: ['! NEW', 'INVALID'] }, result: true },
          { is_hash: { state: ['! INVALID', 'NEW'] }, should_hash: { state: ['! NEW', 'INVALID', 'UNTRACKED'] }, result: false },
        ] },
        { testing: 'icmp', property_name: :icmp, comparisons: [
          { is_hash: { protocol: 'IPv4', icmp: 'echo-reply' }, should_hash: { protocol: 'IPv4', icmp: 0 }, result: true },
          { is_hash: { protocol: 'IPv4', icmp: '0' }, should_hash: { protocol: 'IPv4', icmp: 'echo-reply' }, result: true },
          { is_hash: { protocol: 'IPv6', icmp: 'echo-reply' }, should_hash: { protocol: 'IPv6', icmp: 129 }, result: true },
          { is_hash: { protocol: 'IPv6', icmp: '129' }, should_hash: { protocol: 'IPv6', icmp: 129 }, result: true },
          { is_hash: { protocol: 'IPv4', icmp: 'echo-reply' }, should_hash: { protocol: 'IPv4', icmp: 'echo-reply' }, result: true },
          { is_hash: { protocol: 'IPv4', icmp: '3' }, should_hash: { protocol: 'IPv4', icmp: 'echo-reply' }, result: false },
        ] },
        { testing: 'log_level', property_name: :log_level, comparisons: [
          { is_hash: { log_level: 'alert' }, should_hash: { log_level: 1 }, result: true },
          { is_hash: { log_level: 'alert' }, should_hash: { log_level: 'alert' }, result: true },
          { is_hash: { log_level: '1' }, should_hash: { log_level: 'alert' }, result: true },
          { is_hash: { log_level: '1' }, should_hash: { log_level: 1 }, result: true },
          { is_hash: { log_level: '1' }, should_hash: { log_level: 'err' }, result: false },
        ] },
        { testing: 'set_mark', property_name: :set_mark, comparisons: [
          { is_hash: { set_mark: '42/42' }, should_hash: { set_mark: '0x2a/0x2a' }, result: true },
          { is_hash: { set_mark: '0x2a/0x2a' }, should_hash: { set_mark: '42/42' }, result: true },
          { is_hash: { set_mark: '0x2a/0xffffffff' }, should_hash: { set_mark: '0x2a' }, result: true },
          { is_hash: { set_mark: '0x2a/0x2a' }, should_hash: { set_mark: '0x2a/0x2a' }, result: true },
          { is_hash: { set_mark: '0x2a/0xffffffff' }, should_hash: { set_mark: '0x2a/0x2a' }, result: false },
        ] },
        { testing: 'match_mark/connmark', property_name: :match_mark, comparisons: [
          { is_hash: { match_mark: 42 }, should_hash: { match_mark: '0x2a' }, result: true },
          { is_hash: { match_mark: '0x2a' }, should_hash: { match_mark: '42' }, result: true },
          { is_hash: { match_mark: 42 }, should_hash: { match_mark: '42' }, result: true },
          { is_hash: { match_mark: '0x2a' }, should_hash: { match_mark: '0x2a' }, result: true },
          { is_hash: { match_mark: '0x2a' }, should_hash: { match_mark: 43 }, result: false },
        ] },
        { testing: 'time_start/time_stop', property_name: :time_start, comparisons: [
          { is_hash: { time_start: '04:20:00' }, should_hash: { time_start: '4:20' }, result: true },
          { is_hash: { time_start: '04:20:00' }, should_hash: { time_start: '04:20' }, result: true },
          { is_hash: { time_start: '04:20:00' }, should_hash: { time_start: '4:20:00' }, result: true },
          { is_hash: { time_start: '04:20:00' }, should_hash: { time_start: '4:20:30' }, result: false },
        ] },
        { testing: 'jump', property_name: :jump, comparisons: [
          { is_hash: { jump: 'ACCEPT' }, should_hash: { jump: 'ACCEPT' }, result: true },
          { is_hash: { jump: 'ACCEPT' }, should_hash: { jump: 'accept' }, result: true },
          { is_hash: { jump: 'accept' }, should_hash: { jump: 'accept' }, result: true },
          { is_hash: { jump: 'accept' }, should_hash: { jump: 'drop' }, result: false },
        ] },
        { testing: 'dport/sport', property_name: :dport, comparisons: [
          { is_hash: { dport: '! 50' }, should_hash: { dport: '! 50' }, result: true },
          { is_hash: { dport: '50:60' }, should_hash: { dport: '50-60' }, result: true },
          { is_hash: { dport: ['50:60'] }, should_hash: { dport: '50-60' }, result: true },
          { is_hash: { dport: ['50:60'] }, should_hash: { dport: ['50-60'] }, result: true },
          { is_hash: { dport: ['! 50:60', '90'] }, should_hash: { dport: ['! 90', '50-60'] }, result: true },
          { is_hash: { dport: '50' }, should_hash: { dport: '90' }, result: false },
        ] },
        { testing: 'string_hex', property_name: :string_hex, comparisons: [
          { is_hash: { string_hex: '! |f4 6d 04 25 b2 02 00 0a|' }, should_hash: { string_hex: '! |f46d0425b202000a|' }, result: true },
          { is_hash: { string_hex: '|f46d0425b202000a|' }, should_hash: { string_hex: '|f4 6d 04 25 b2 02 00 0a|' }, result: true },
          { is_hash: { string_hex: '|f4 6d 04 25 b2 02 00 0a|' }, should_hash: { string_hex: '|f4 6d 04 25 b2 02 00 0a|' }, result: true },
        ] },
        # if both values are arrays
        { testing: 'when comparing arrays', property_name: :week_days, comparisons: [
          { is_hash: { week_days: ['Mon', 'Tue', 'Wed'] }, should_hash: { week_days: ['Tue', 'Mon', 'Wed'] }, result: true },
          { is_hash: { week_days: ['Tue', 'Wed', 'Mon'] }, should_hash: { week_days: ['Tue', 'Mon', 'Wed'] }, result: true },
        ] },
        # if not needed; either value is nil or only one is an array
        { testing: 'when defaulting to the standard comparison', property_name: :stat_packet, comparisons: [
          { is_hash: { stat_packet: 313 }, should_hash: { stat_packet: 313 }, result: nil },
          { is_hash: { stat_packet: 313 }, should_hash: { stat_packet: 42 }, result: nil },
        ] },
      ].each do |test|
        context "with attributes: '#{test[:testing]}'" do
          test[:comparisons].each do |comparison|
            it comparison do
              expect(context).to receive(:debug).with(%r{\AChecking whether '#{test[:property_name]}'})
              expect(provider.insync?(context, '001 Test Rule', test[:property_name], comparison[:is_hash], comparison[:should_hash])).to eql(comparison[:result])
            end
          end
        end
      end
    end
  end
end
