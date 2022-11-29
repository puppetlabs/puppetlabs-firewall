# frozen_string_literal: true

require 'spec_helper'

describe 'Facter::Util::Fact' do
  before(:each) do
    Facter.clear
    allow(Facter.fact(:kernel)).to receive(:value).and_return('Linux')
    allow(Facter.fact(:kernelrelease)).to receive(:value).and_return('2.6')
  end

  describe 'iptables_version' do
    it {
      allow(Facter::Core::Execution).to receive(:which)
        .with('iptables').and_return('/usr/sbin/iptables')
      allow(Facter::Core::Execution).to receive(:execute)
        .with('iptables --version', { on_fail: nil }).and_return('iptables v1.4.7')
      expect(Facter.fact(:iptables_version).value).to eql '1.4.7'
    }
  end

  describe 'ip6tables_version' do
    before(:each) do
      allow(Facter::Core::Execution).to receive(:which)
        .with('ip6tables').and_return('/usr/sbin/ip6tables')
      allow(Facter::Core::Execution).to receive(:execute)
        .with('ip6tables --version', { on_fail: nil }).and_return('ip6tables v1.4.7')
    end
    it { expect(Facter.fact(:ip6tables_version).value).to eql '1.4.7' }
  end
end
