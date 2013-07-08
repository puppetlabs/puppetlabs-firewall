#!/usr/bin/env rspec

require 'spec_helper'
require 'puppet/provider/confine/exists'

describe 'iptables provider detection' do
  let(:exists) {
    Puppet::Provider::Confine::Exists
  }

  before :each do
    # Reset the default provider
    Puppet::Type.type(:firewall).defaultprovider = nil
  end

  it "should default to iptables provider if /sbin/iptables[-save] exists" do
    # Stub lookup for /sbin/iptables & /sbin/iptables-save
    allow(exists).to receive(:which).with("iptables").
      and_return "/sbin/iptables"
    allow(exists).to receive(:which).with("iptables-save").
      and_return "/sbin/iptables-save"

    # Every other command should return false so we don't pick up any
    # other providers
    allow(exists).to receive(:which).with() { |value|
      ! ["iptables","iptables-save"].include?(value)
    }.and_return false

    # Create a resource instance and make sure the provider is iptables
    resource = Puppet::Type.type(:firewall).new({
      :name => '000 test foo',
    })
    expect(resource.provider.class.to_s).to eq("Puppet::Type::Firewall::ProviderIptables")
  end
end

describe 'iptables provider' do
  let(:provider) { Puppet::Type.type(:firewall).provider(:iptables) }
  let(:resource) {
    Puppet::Type.type(:firewall).new({
      :name  => '000 test foo',
      :action  => 'accept',
    })
  }

  before :each do
    Puppet::Type::Firewall.stubs(:defaultprovider).returns provider
    allow(provider).to receive(:command).with(:iptables_save).and_return "/sbin/iptables-save"

    # Stub iptables version
    allow(Facter.fact(:iptables_version)).to receive(:value).and_return("1.4.2")

    allow(Puppet::Util::Execution).to receive(:execute).and_return ""
    allow(Puppet::Util).to receive(:which).with("iptables-save").
      and_return "/sbin/iptables-save"
  end

  it 'should be able to get a list of existing rules' do
    provider.instances.each do |rule|
      expect(rule).to be_instance_of(provider)
      expect(rule.properties[:provider].to_s).to eq(provider.name.to_s)
    end
  end

  it 'should ignore lines with fatal errors' do
    allow(Puppet::Util::Execution).to receive(:execute).with(['/sbin/iptables-save']).
      and_return("FATAL: Could not load /lib/modules/2.6.18-028stab095.1/modules.dep: No such file or directory")

    expect(provider.instances.length).to be_zero
  end

  # Load in ruby hash for test fixtures.
  load 'spec/fixtures/iptables/conversion_hash.rb'

  describe 'when converting rules to resources' do
    ARGS_TO_HASH.each do |test_name,data|
      describe "for test data '#{test_name}'" do
        let(:resource) { provider.rule_to_hash(data[:line], data[:table], 0) }

        # If this option is enabled, make sure the parameters exactly match
        if data[:compare_all] then
          it "the parameter hash keys should be the same as returned by rules_to_hash" do
            expect(resource.keys).to match_array(data[:params].keys)
          end
        end

        # Iterate across each parameter, creating an example for comparison
        data[:params].each do |param_name, param_value|
          it "the parameter '#{param_name.to_s}' should match #{param_value.inspect}" do
            # booleans get cludged to string "true"
            if param_value == true then
              expect(resource[param_name]).to be_true
            else
              expect(resource[param_name]).to eq(data[:params][param_name])
            end
          end
        end
      end
    end
  end

  describe 'when working out general_args' do
    HASH_TO_ARGS.each do |test_name,data|
      describe "for test data '#{test_name}'" do
        let(:resource) { Puppet::Type.type(:firewall).new(data[:params]) }
        let(:provider) { Puppet::Type.type(:firewall).provider(:iptables) }
        let(:instance) { provider.new(resource) }

        it 'general_args should be valid' do
          expect(instance.general_args.flatten).to eq(data[:args])
        end
      end
    end
  end

  describe 'when converting rules without comments to resources' do
    let(:sample_rule) {
      '-A INPUT -s 1.1.1.1 -d 1.1.1.1 -p tcp -m multiport --dports 7061,7062 -m multiport --sports 7061,7062 -j ACCEPT'
    }
    let(:resource) { provider.rule_to_hash(sample_rule, 'filter', 0) }
    let(:instance) { provider.new(resource) }

    it 'rule name contains a MD5 sum of the line' do
      expect(resource[:name]).to eq("9000 #{Digest::MD5.hexdigest(resource[:line])}")
    end
  end

  describe 'when creating resources' do
    let(:instance) { provider.new(resource) }

    it 'insert_args should be an array' do
      expect(instance.insert_args.class).to eq(Array)
    end
  end

  describe 'when modifying resources' do
    let(:instance) { provider.new(resource) }

    it 'update_args should be an array' do
      expect(instance.update_args.class).to eq(Array)
    end
  end

  describe 'when deleting resources' do
    let(:sample_rule) {
      '-A INPUT -s 1.1.1.1 -d 1.1.1.1 -p tcp -m multiport --dports 7061,7062 -m multiport --sports 7061,7062 -j ACCEPT'
    }
    let(:resource) { provider.rule_to_hash(sample_rule, 'filter', 0) }
    let(:instance) { provider.new(resource) }

    it 'resource[:line] looks like the original rule' do
      resource[:line] == sample_rule
    end

    it 'delete_args is an array' do
      expect(instance.delete_args.class).to eq(Array)
    end

    it 'delete_args is the same as the rule string when joined' do
      expect(instance.delete_args.join(' ')).to eq(sample_rule.gsub(/\-A/,
        '-t filter -D'))
    end
  end
end
