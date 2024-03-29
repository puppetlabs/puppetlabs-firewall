# frozen_string_literal: true

require 'puppet_x'
require 'spec_helper'
require 'puppet_x/puppetlabs/firewall/ipcidr'

RSpec.describe PuppetX::Firewall::IPCidr do # rubocop:disable RSpec/FilePath
  let(:ipcidr) { described_class }

  describe 'ipv4 address' do
    subject(:host) { ipaddr }

    let(:ipaddr) { ipcidr.new('96.126.112.51') }

    it { expect(host.cidr).to eql '96.126.112.51/32' }
    it { expect(host.prefixlen).to be 32 }
    it { expect(host.netmask).to eql '255.255.255.255' }
  end

  describe 'single ipv4 address with cidr' do
    subject(:host) { ipaddr }

    let(:ipaddr) { ipcidr.new('96.126.112.51/32') }

    it { expect(host.cidr).to eql '96.126.112.51/32' }
    it { expect(host.prefixlen).to be 32 }
    it { expect(host.netmask).to eql '255.255.255.255' }
  end

  describe 'ipv4 address range with cidr' do
    subject(:host) { ipaddr }

    let(:ipaddr) { ipcidr.new('96.126.112.0/24') }

    it { expect(host.cidr).to eql '96.126.112.0/24' }
    it { expect(host.prefixlen).to be 24 }
    it { expect(host.netmask).to eql '255.255.255.0' }
  end

  # https://tickets.puppetlabs.com/browse/MODULES-3215
  describe 'ipv4 address range with invalid cidr' do
    subject(:host) { ipaddr }

    let(:ipaddr) { ipcidr.new('96.126.112.20/24') }

    it { expect(host.cidr).to eq '96.126.112.0/24' } # .20 is expected to be silently dropped.
    it { expect(host.prefixlen).to be 24 }
    it { expect(host.netmask).to eql '255.255.255.0' }
  end

  describe 'ipv4 open range with cidr' do
    subject(:host) { ipaddr }

    let(:ipaddr) { ipcidr.new('0.0.0.0/0') }

    it { expect(host.cidr).to eql '0.0.0.0/0' }
    it { expect(host.prefixlen).to be 0 }
    it { expect(host.netmask).to eql '0.0.0.0' }
  end

  describe 'ipv4 invalid address' do
    subject(:host) { ipcidr.new('256.168.2.0/24') }

    it { expect { host }.to raise_error ArgumentError, %r{256.168.2.0/24} }
  end

  describe 'ipv6 address' do
    subject(:host) { ipaddr }

    let(:ipaddr) { ipcidr.new('2001:db8:85a3:0:0:8a2e:370:7334') }

    it { expect(host.cidr).to eql '2001:db8:85a3::8a2e:370:7334/128' }
    it { expect(host.prefixlen).to be 128 }
    it { expect(host.netmask).to eql 'ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff' }
  end

  describe 'single ipv6 addr with cidr' do
    subject(:host) { ipaddr }

    let(:ipaddr) { ipcidr.new('2001:db8:85a3:0:0:8a2e:370:7334/128') }

    it { expect(host.cidr).to eql '2001:db8:85a3::8a2e:370:7334/128' }
    it { expect(host.prefixlen).to be 128 }
    it { expect(host.netmask).to eql 'ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff' }
  end

  describe 'ipv6 addr range with cidr' do
    subject(:host) { ipaddr }

    let(:ipaddr) { ipcidr.new('2001:db8:1234::/48') }

    it { expect(host.cidr).to eql '2001:db8:1234::/48' }
    it { expect(host.prefixlen).to be 48 }
    it { expect(host.netmask).to eql 'ffff:ffff:ffff:0000:0000:0000:0000:0000' }
  end

  describe 'ipv6 open range with cidr' do
    subject(:host) { ipaddr }

    let(:ipaddr) { ipcidr.new('::/0') }

    it { expect(host.cidr).to eql '::/0' }
    it { expect(host.prefixlen).to be 0 }
    it { expect(host.netmask).to eql '0000:0000:0000:0000:0000:0000:0000:0000' }
  end
end
