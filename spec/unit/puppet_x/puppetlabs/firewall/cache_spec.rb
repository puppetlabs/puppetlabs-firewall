# frozen_string_literal: true

require 'spec_helper'
require 'puppet_x/puppetlabs/firewall/cache'

RSpec.describe PuppetX::Firewall::Cache do
  let(:environment) { instance_double(Puppet::Node::Environment) }

  context 'when a run context is available' do
    before(:each) do
      allow(Puppet).to receive(:lookup).and_call_original
      allow(Puppet).to receive(:lookup).with(:current_environment).and_return(environment)
    end

    it 'computes the value once per key' do
      calls = 0
      2.times { described_class.fetch(:key) { calls += 1 } }
      expect(calls).to eq(1)
    end

    it 'returns the cached value on subsequent fetches' do
      described_class.fetch(:key) { 'value' }
      expect(described_class.fetch(:key) { 'other' }).to eq('value')
    end

    it 'computes separate values for separate keys' do
      described_class.fetch(:one) { 'first' }
      expect(described_class.fetch(:two) { 'second' }).to eq('second')
    end

    it 'recomputes after invalidate' do
      described_class.fetch(:key) { 'value' }
      described_class.invalidate
      expect(described_class.fetch(:key) { 'other' }).to eq('other')
    end

    it 'recomputes when the run context changes' do
      other_environment = instance_double(Puppet::Node::Environment)
      described_class.fetch(:key) { 'value' }
      allow(Puppet).to receive(:lookup).with(:current_environment).and_return(other_environment)
      expect(described_class.fetch(:key) { 'other' }).to eq('other')
    end
  end

  context 'when no run context is available' do
    before(:each) do
      allow(Puppet).to receive(:lookup).and_call_original
      allow(Puppet).to receive(:lookup).with(:current_environment).and_return(nil)
    end

    it 'computes the value every time' do
      calls = 0
      2.times { described_class.fetch(:key) { calls += 1 } }
      expect(calls).to eq(2)
    end
  end

  context 'when looking up the run context raises' do
    before(:each) do
      allow(Puppet).to receive(:lookup).and_call_original
      allow(Puppet).to receive(:lookup).with(:current_environment).and_raise(Puppet::Error, 'no context')
    end

    it 'computes the value every time' do
      calls = 0
      2.times { described_class.fetch(:key) { calls += 1 } }
      expect(calls).to eq(2)
    end
  end
end
