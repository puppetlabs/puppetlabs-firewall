# frozen_string_literal: true

require 'puppet_x'
require 'spec_helper'
require 'puppet/resource_api'
require 'puppet_x/puppetlabs/firewall/utility'

RSpec.describe PuppetX::Firewall::Utility do # rubocop:disable RSpec/FilePath
  let(:utility) { described_class }

  describe '#persist_iptables' do
    before(:each) { Facter.clear }

    let(:context) { Puppet::ResourceApi::PuppetContext.new(Puppet::Type.type('firewall').type_definition.definition) }

    context 'when proto is IPv4' do
      let(:proto) { 'IPv4' }

      it 'and OS family is RedHat' do
        allow(Facter.fact('os')).to receive(:value).and_return({ 'family' => 'RedHat' })
        expect(Puppet::Provider).to receive(:execute).with(['/usr/libexec/iptables/iptables.init', 'save'])

        utility.persist_iptables(context, 'test', proto)
      end

      it 'and OS family is Debian' do
        allow(Facter.fact('os')).to receive(:value).and_return({ 'family' => 'Debian' })
        allow(Facter.fact(:iptables_persistent_version)).to receive(:value).and_return('0.4')
        expect(Puppet::Provider).to receive(:execute).with(['/usr/sbin/service', 'iptables-persistent', 'save'])

        utility.persist_iptables(context, 'test', proto)
      end

      it 'and OS family is Archlinux' do
        allow(Facter.fact('os')).to receive(:value).and_return({ 'family' => 'Archlinux' })
        expect(Puppet::Provider).to receive(:execute).with(['/bin/sh', '-c', '/usr/sbin/iptables-save > /etc/iptables/iptables.rules'])

        utility.persist_iptables(context, 'test', proto)
      end

      it 'and OS family is Suse' do
        allow(Facter.fact('os')).to receive(:value).and_return({ 'family' => 'Suse' })
        expect(Puppet::Provider).to receive(:execute).with(['/bin/sh', '-c', '/usr/sbin/iptables-save > /etc/sysconfig/iptables'])

        utility.persist_iptables(context, 'test', proto)
      end
    end

    context 'when proto is IPv6' do
      let(:proto) { 'IPv6' }

      it 'and OS family is RedHat' do
        allow(Facter.fact('os')).to receive(:value).and_return({ 'family' => 'RedHat' })
        expect(Puppet::Provider).to receive(:execute).with(['/usr/libexec/iptables/ip6tables.init', 'save'])

        utility.persist_iptables(context, 'test', proto)
      end

      it 'and OS family is Debian' do
        allow(Facter.fact('os')).to receive(:value).and_return({ 'family' => 'Debian' })
        allow(Facter.fact(:iptables_persistent_version)).to receive(:value).and_return('1.2')
        expect(Puppet::Provider).to receive(:execute).with(['/usr/sbin/service', 'netfilter-persistent', 'save'])

        utility.persist_iptables(context, 'test', proto)
      end

      it 'and OS family is Archlinux' do
        allow(Facter.fact('os')).to receive(:value).and_return({ 'family' => 'Archlinux' })
        expect(Puppet::Provider).to receive(:execute).with(['/bin/sh', '-c', '/usr/sbin/ip6tables-save > /etc/iptables/ip6tables.rules'])

        utility.persist_iptables(context, 'test', proto)
      end
    end
  end

  describe '#create_absent' do
    it {
      expect(utility.create_absent(:name, { chain: 'INPUT', table: 'filter', protocol: 'IPv4' })).to eql({ chain: 'INPUT', table: 'filter', protocol: 'IPv4', ensure: 'absent' })
    }

    it { expect(utility.create_absent(:name, 'test')).to eql({ name: 'test', ensure: 'absent' }) }
  end

  describe '#host_to_ip' do
    it {
      allow(Resolv).to receive(:each_address).at_least(:once).with('puppetlabs.com').and_yield('96.126.112.51').and_yield('2001:DB8:4650::13:8A')
      expect(utility.host_to_ip('puppetlabs.com', 'IPv4')).to eql '96.126.112.51/32'
      expect(utility.host_to_ip('puppetlabs.com', 'IPv6')).to eql '2001:db8:4650::13:8a/128'
    }

    it { expect(utility.host_to_ip('96.126.112.51')).to eql '96.126.112.51/32' }
    it { expect(utility.host_to_ip('96.126.112.51/32')).to eql '96.126.112.51/32' }
    it { expect(utility.host_to_ip('2001:db8:85a3:0:0:8a2e:370:7334')).to eql '2001:db8:85a3::8a2e:370:7334/128' }
    it { expect(utility.host_to_ip('2001:db8:1234::/48')).to eql '2001:db8:1234::/48' }
    it { expect(utility.host_to_ip('0.0.0.0/0')).to be_nil }
    it { expect(utility.host_to_ip('::/0')).to be_nil }
  end

  describe '#host_to_mask' do
    it {
      allow(Resolv).to receive(:each_address).at_least(:once).with('puppetlabs.com').and_yield('96.126.112.51').and_yield('2001:DB8:4650::13:8A')
      expect(utility.host_to_mask('puppetlabs.com', 'IPv4')).to eql '96.126.112.51/32'
      expect(utility.host_to_mask('! puppetlabs.com', 'IPv6')).to eql '! 2001:db8:4650::13:8a/128'
    }

    it { expect(utility.host_to_mask('96.126.112.51', 'IPv4')).to eql '96.126.112.51/32' }
    it { expect(utility.host_to_mask('!96.126.112.51', 'IPv4')).to eql '! 96.126.112.51/32' }
    it { expect(utility.host_to_mask('96.126.112.51/32', 'IPv4')).to eql '96.126.112.51/32' }
    it { expect(utility.host_to_mask('! 96.126.112.51/32', 'IPv4')).to eql '! 96.126.112.51/32' }
    it { expect(utility.host_to_mask('2001:db8:85a3:0:0:8a2e:370:7334', 'IPv6')).to eql '2001:db8:85a3::8a2e:370:7334/128' }
    it { expect(utility.host_to_mask('!2001:db8:85a3:0:0:8a2e:370:7334', 'IPv6')).to eql '! 2001:db8:85a3::8a2e:370:7334/128' }
    it { expect(utility.host_to_mask('2001:db8:1234::/48', 'IPv6')).to eql '2001:db8:1234::/48' }
    it { expect(utility.host_to_mask('! 2001:db8:1234::/48', 'IPv6')).to eql '! 2001:db8:1234::/48' }
    it { expect(utility.host_to_mask('0.0.0.0/0', 'IPv4')).to be_nil }
    it { expect(utility.host_to_mask('!0.0.0.0/0', 'IPv4')).to be_nil }
    it { expect(utility.host_to_mask('::/0', 'IPv6')).to be_nil }
    it { expect(utility.host_to_mask('! ::/0', 'IPv6')).to be_nil }
  end

  describe '#icmp_name_to_number' do
    context 'with proto unsupported' do
      ['inet5', 'inet8', 'foo'].each do |proto|
        it "rejects invalid proto #{proto}" do
          expect { utility.icmp_name_to_number('echo-reply', proto) }
            .to raise_error(ArgumentError, "unsupported protocol family '#{proto}'")
        end
      end
    end

    context 'with proto IPv4' do
      let(:proto) { 'IPv4' }

      it { expect(utility.icmp_name_to_number('echo-reply', proto)).to eql '0' }
      it { expect(utility.icmp_name_to_number('destination-unreachable', proto)).to eql '3' }
      it { expect(utility.icmp_name_to_number('source-quench', proto)).to eql '4' }
      it { expect(utility.icmp_name_to_number('redirect', proto)).to eql '6' }
      it { expect(utility.icmp_name_to_number('echo-request', proto)).to eql '8' }
      it { expect(utility.icmp_name_to_number('router-advertisement', proto)).to eql '9' }
      it { expect(utility.icmp_name_to_number('router-solicitation', proto)).to eql '10' }
      it { expect(utility.icmp_name_to_number('time-exceeded', proto)).to eql '11' }
      it { expect(utility.icmp_name_to_number('parameter-problem', proto)).to eql '12' }
      it { expect(utility.icmp_name_to_number('timestamp-request', proto)).to eql '13' }
      it { expect(utility.icmp_name_to_number('timestamp-reply', proto)).to eql '14' }
      it { expect(utility.icmp_name_to_number('address-mask-request', proto)).to eql '17' }
      it { expect(utility.icmp_name_to_number('address-mask-reply', proto)).to eql '18' }
    end

    context 'with proto IPv6' do
      let(:proto) { 'IPv6' }

      it { expect(utility.icmp_name_to_number('destination-unreachable', proto)).to eql '1' }
      it { expect(utility.icmp_name_to_number('time-exceeded', proto)).to eql '3' }
      it { expect(utility.icmp_name_to_number('parameter-problem', proto)).to eql '4' }
      it { expect(utility.icmp_name_to_number('echo-request', proto)).to eql '128' }
      it { expect(utility.icmp_name_to_number('echo-reply', proto)).to eql '129' }
      it { expect(utility.icmp_name_to_number('router-solicitation', proto)).to eql '133' }
      it { expect(utility.icmp_name_to_number('router-advertisement', proto)).to eql '134' }
      it { expect(utility.icmp_name_to_number('neighbour-solicitation', proto)).to eql '135' }
      it { expect(utility.icmp_name_to_number('neighbour-advertisement', proto)).to eql '136' }
      it { expect(utility.icmp_name_to_number('redirect', proto)).to eql '137' }
    end
  end

  describe '#log_level_name_to_number' do
    it { expect(utility.log_level_name_to_number('2')).to eql '2' }
    it { expect(utility.log_level_name_to_number('4')).to eql '4' }
    it { expect(utility.log_level_name_to_number('panic')).to eql '0' }
    it { expect(utility.log_level_name_to_number('alert')).to eql '1' }
    it { expect(utility.log_level_name_to_number('crit')).to eql '2' }
    it { expect(utility.log_level_name_to_number('err')).to eql '3' }
    it { expect(utility.log_level_name_to_number('warn')).to eql '4' }
    it { expect(utility.log_level_name_to_number('not')).to eql '5' }
    it { expect(utility.log_level_name_to_number('info')).to eql '6' }
    it { expect(utility.log_level_name_to_number('debug')).to eql '7' }
    it { expect(utility.log_level_name_to_number('fail')).to be_nil }
  end

  describe '#to_hex32' do
    it { expect(utility.to_hex32('0')).to eql '0x0' }
    it { expect(utility.to_hex32('0x32')).to eql '0x32' }
    it { expect(utility.to_hex32('42')).to eql '0x2a' }
    it { expect(utility.to_hex32('4294967295')).to eql '0xffffffff' }
    it { expect(utility.to_hex32('4294967296')).to be_nil }
    it { expect(utility.to_hex32('-1')).to be_nil }
    it { expect(utility.to_hex32('bananas')).to be_nil }
  end

  describe '#mark_mask_to_hex' do
    it { expect(utility.mark_mask_to_hex('0')).to eql '0x0/0xffffffff' }
    it { expect(utility.mark_mask_to_hex('0x32/0')).to eql '0x32/0x0' }
    it { expect(utility.mark_mask_to_hex('42')).to eql '0x2a/0xffffffff' }
    it { expect(utility.mark_mask_to_hex('4294967295/42')).to eql '0xffffffff/0x2a' }
  end

  describe '#proto_number_to_name' do
    it { expect(utility.proto_number_to_name('1')).to eql 'icmp' }
    it { expect(utility.proto_number_to_name('2')).to eql 'igmp' }
    it { expect(utility.proto_number_to_name('4')).to eql 'ipencap' }
    it { expect(utility.proto_number_to_name('6')).to eql 'tcp' }
    it { expect(utility.proto_number_to_name('7')).to eql 'cbt' }
    it { expect(utility.proto_number_to_name('17')).to eql 'udp' }
    it { expect(utility.proto_number_to_name('47')).to eql 'gre' }
    it { expect(utility.proto_number_to_name('50')).to eql 'esp' }
    it { expect(utility.proto_number_to_name('51')).to eql 'ah' }
    it { expect(utility.proto_number_to_name('89')).to eql 'ospf' }
    it { expect(utility.proto_number_to_name('103')).to eql 'pim' }
    it { expect(utility.proto_number_to_name('112')).to eql 'vrrp' }
    it { expect(utility.proto_number_to_name('132')).to eql 'sctp' }

    it 'rejects invalid number 619' do
      expect { utility.proto_number_to_name('619') }.to raise_error(ArgumentError, 'Unsupported proto number: 619')
    end
  end

  describe '#dscp_number_to_class' do
    it { expect(utility.dscp_number_to_class('0x0a')).to eql 'af11' }
    it { expect(utility.dscp_number_to_class('0x0c')).to eql 'af12' }
    it { expect(utility.dscp_number_to_class('0x0e')).to eql 'af13' }
    it { expect(utility.dscp_number_to_class('0x12')).to eql 'af21' }
    it { expect(utility.dscp_number_to_class('0x14')).to eql 'af22' }
    it { expect(utility.dscp_number_to_class('0x16')).to eql 'af23' }
    it { expect(utility.dscp_number_to_class('0x1a')).to eql 'af31' }
    it { expect(utility.dscp_number_to_class('0x1c')).to eql 'af32' }
    it { expect(utility.dscp_number_to_class('0x1e')).to eql 'af33' }
    it { expect(utility.dscp_number_to_class('0x22')).to eql 'af41' }
    it { expect(utility.dscp_number_to_class('0x24')).to eql 'af42' }
    it { expect(utility.dscp_number_to_class('0x26')).to eql 'af43' }
    it { expect(utility.dscp_number_to_class('0x08')).to eql 'cs1' }
    it { expect(utility.dscp_number_to_class('0x10')).to eql 'cs2' }
    it { expect(utility.dscp_number_to_class('0x18')).to eql 'cs3' }
    it { expect(utility.dscp_number_to_class('0x20')).to eql 'cs4' }
    it { expect(utility.dscp_number_to_class('0x28')).to eql 'cs5' }
    it { expect(utility.dscp_number_to_class('0x30')).to eql 'cs6' }
    it { expect(utility.dscp_number_to_class('0x38')).to eql 'cs7' }
    it { expect(utility.dscp_number_to_class('0x2e')).to eql 'ef' }
    it { expect(utility.dscp_number_to_class('0x66')).to be_nil }
  end
end
