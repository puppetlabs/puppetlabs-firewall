#!/usr/bin/env rspec # rubocop:disable Lint/ScriptPermission : Puppet error?
# frozen_string_literal: true

require 'spec_helper'
require 'puppet/confine/exists'

provider_class = Puppet::Type.type(:firewall).provider(:ip6tables)
describe 'ip6tables' do # rubocop:disable RSpec/MultipleDescribes
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
    allow(Facter.fact('ip6tables_version')).to receive(:value).and_return(ip6tables_version)
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

describe 'ip6tables provider' do
  let(:provider6) { Puppet::Type.type(:firewall).provider(:ip6tables) }
  let(:resource) do
    Puppet::Type.type(:firewall).new(name: '000 test foo',
                                     action: 'accept',
                                     provider: 'ip6tables')
  end

  before :each do
    allow(Puppet::Type::Firewall).to receive(:ip6tables).and_return provider6
    allow(provider6).to receive(:command).with(:ip6tables_save).and_return '/sbin/ip6tables-save'

    # Stub iptables version
    allow(Facter.fact(:ip6tables_version)).to receive(:value).and_return '1.4.7'

    allow(Puppet::Util::Execution).to receive(:execute).and_return ''
    allow(Puppet::Util).to receive(:which).with('ip6tables-save')
                                          .and_return '/sbin/ip6tables-save'
  end

  it 'is expected to be able to get a list of existing rules' do
    provider6.instances.each do |rule|
      expect(rule).to be_instance_of(provider6)
      expect(rule.properties[:provider6].to_s).to eql provider6.name.to_s
    end
  end

  it 'is expected to ignore lines with fatal errors' do
    allow(Puppet::Util::Execution).to receive(:execute).with(['/sbin/ip6tables-save'])
                                                       .and_return('FATAL: Could not load /lib/modules/2.6.18-028stab095.1/modules.dep: No such file or directory')
    expect(provider6.instances.length).to eq 0
  end

  # Load in ruby hash for test fixtures.
  load 'spec/fixtures/ip6tables/conversion_hash.rb'

  describe 'when converting rules to resources' do
    ARGS_TO_HASH6.each do |test_name, data|
      describe "for test data '#{test_name}'" do
        let(:resource) { provider6.rule_to_hash(data[:line], data[:table], 0) }

        # If this option is enabled, make sure the parameters exactly match
        if data[:compare_all]
          it 'the parameter hash keys should be the same as returned by rules_to_hash' do
            expect(resource.keys).to match_array(data[:params].keys)
          end
        end

        # Iterate across each parameter, creating an example for comparison
        data[:params].each do |param_name, param_value|
          it "the parameter '#{param_name}' should match #{param_value.inspect}" do
            if param_value == true
              expect(resource[param_name]).to be_truthy
            else
              expect(resource[param_name]).to eq(data[:params][param_name])
            end
          end
        end
      end
    end
  end

  describe 'when working out general_args' do
    HASH_TO_ARGS6.each do |test_name, data|
      describe "for test data '#{test_name}'" do
        let(:resource) { Puppet::Type.type(:firewall).new(data[:params]) }
        let(:provider6) { Puppet::Type.type(:firewall).provider(:ip6tables) }
        let(:instance) { provider6.new(resource) }

        it 'general_args should be valid' do
          data[:args].unshift('--wait') if instance.general_args.flatten.include? '--wait'
          expect(instance.general_args.flatten).to eql data[:args]
        end
      end
    end
  end

  describe 'when deleting ipv6 resources' do
    let(:sample_rule) do
      '-A INPUT -i lo -m comment --comment "001 accept all to lo interface v6" -j ACCEPT'
    end

    let(:bare_sample_rule) do
      '-A INPUT -i lo -m comment --comment 001 accept all to lo interface v6 -j ACCEPT'
    end

    let(:resource) { provider6.rule_to_hash(sample_rule, 'filter', 0) }
    let(:instance) { provider6.new(resource) }

    it 'resource[:line] looks like the original rule' do
      resource[:line] == sample_rule
    end

    it 'delete_args is an array' do
      expect(instance.delete_args.class).to eq(Array)
    end
  end
end
