#!/usr/bin/env rspec # rubocop:disable Lint/ScriptPermission : Puppet error?
# frozen_string_literal: true

require 'spec_helper'
require 'puppet/confine/exists'

provider_class = Puppet::Type.type(:firewall).provider(:ip6tables)
describe 'ip6tables' do
  let(:params) { { name: '000 test foo', action: 'accept' } }
  let(:provider) { provider_class }
  let(:resource) { Puppet::Type.type(:firewall) }
  let(:ip6tables_version) { '1.4.0' }

  before :each do
  end

  def stub_iptables
    allow(Puppet::Type::Firewall).to receive(:defaultprovider).and_return provider
    # Stub confine facts
    allow(provider).to receive(:command).with(:iptables_save).and_return '/sbin/iptables-save'

    allow(Facter.fact(:kernel)).to receive(:value).and_return('Linux')
    allow(Facter.fact(:operatingsystem)).to receive(:value).and_return('Debian')
    stub_const('Ip6tables_version', ip6tables_version)
    allow(Puppet::Util::Execution).to receive(:execute).and_return ''
    allow(Puppet::Util).to receive(:which).with('iptables-save')
                                          .and_return '/sbin/iptables-save'
  end

  shared_examples 'raise error' do
    it {
      stub_iptables
      expect {
        provider.new(resource.new(params))
      }.to raise_error(Puppet::DevError, error_message)
    }
  end
  shared_examples 'run' do
    it {
      stub_iptables
      provider.new(resource.new(params))
    }
  end
  context 'when iptables 1.3' do
    let(:params) { { name: '000 test foo', action: 'accept' } }
    let(:error_message) { %r{The ip6tables provider is not supported on version 1\.3 of iptables} }
    let(:ip6tables_version) { '1.3.10' }

    it_behaves_like 'raise error'
  end
  context 'when ip6tables nil' do
    let(:params) { { name: '000 test foo', action: 'accept' } }
    let(:error_message) { %r{The ip6tables provider is not supported on version 1\.3 of iptables} }
    let(:ip6tables_version) { nil }

    it_behaves_like 'run'
  end
end
