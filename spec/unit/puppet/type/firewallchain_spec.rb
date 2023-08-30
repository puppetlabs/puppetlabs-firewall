# frozen_string_literal: true

require 'spec_helper'
require 'puppet/type/firewallchain'

RSpec.describe 'firewallchain type' do
  let(:firewallchain) { Puppet::Type.type(:firewallchain) }

  it 'loads' do
    expect(firewallchain).not_to be_nil
  end

  it 'has :name be its namevar' do
    expect(firewallchain.key_attributes).to eql [:name]
  end

  describe ':ensure' do
    context 'when given valid input' do
      ['present', 'absent'].each do |input|
        it input do
          expect { firewallchain.new(name: 'INPUT:filter:IPv4', ensure: input) }.not_to raise_error
        end
      end
    end

    context 'when given invalid input' do
      [true, 123, 'false'].each do |input|
        it input do
          expect { firewallchain.new(name: 'INPUT:filter:IPv4', ensure: input) }.to raise_error(Puppet::Error)
        end
      end
    end
  end

  describe ':name' do
    context 'when given valid input' do
      ['INPUT:filter:IPv4', 'FORWARD:mangle:IPv6', 'PREROUTING:nat:IPv4', 'INPUT:filter:IPv6', 'OUTPUT:raw:IPv6',
       'BROUTING:broute:ethernet', 'test_chain:security:IPv4'].each do |input|
        it input do
          expect { firewallchain.new(name: input) }.not_to raise_error
        end
      end
    end

    context 'when given invalid input' do
      ['INPUT:filter:IPv', 'FORWARD:glee:IPv6', 'PREROUTING:nat:iptables', 'INPUT:filter:Iv6', true,
       123, ':glee:IPv6'].each do |input|
        it input do
          expect { firewallchain.new(name: input) }.to raise_error(Puppet::Error)
        end
      end
    end
  end

  describe 'policy' do
    context 'when given valid input' do
      ['accept', 'drop', 'queue', 'return'].each do |input|
        it input do
          expect { firewallchain.new(name: 'INPUT:filter:IPv4', policy: input) }.not_to raise_error
        end
      end
    end

    context 'when given invalid input' do
      ['acquise', true, 123].each do |input|
        it input do
          expect { firewallchain.new(name: 'INPUT:filter:IPv4', policy: input) }.to raise_error(Puppet::Error)
        end
      end
    end
  end

  describe 'purge' do
    context 'when given valid input' do
      [true, false].each do |input|
        it input do
          expect { firewallchain.new(name: 'INPUT:filter:IPv4', purge: input) }.not_to raise_error
        end
      end
    end

    context 'when given invalid input' do
      ['true', 'false', 123].each do |input|
        it input do
          expect { firewallchain.new(name: 'INPUT:filter:IPv4', purge: input) }.to raise_error(Puppet::Error)
        end
      end
    end
  end

  describe 'ignore' do
    context 'when given valid input' do
      ['(?i)foo', ['(?i)foo', '(?i:foo)']].each do |input|
        it input do
          expect { firewallchain.new(name: 'INPUT:filter:IPv4', purge: true, ignore: input) }.not_to raise_error
        end
      end
    end

    context 'when given invalid input' do
      [true, 123, ''].each do |input|
        it input do
          expect { firewallchain.new(name: 'INPUT:filter:IPv4', purge: true, ignore: input) }.to raise_error(Puppet::Error)
        end
      end
    end
  end

  describe 'ignore_foreign' do
    context 'when given valid input' do
      [true, false].each do |input|
        it input do
          expect { firewallchain.new(name: 'INPUT:filter:IPv4', purge: true, ignore_foreign: input) }.not_to raise_error
        end
      end
    end

    context 'when given invalid input' do
      ['true', 'false', 123].each do |input|
        it input do
          expect { firewallchain.new(name: 'INPUT:filter:IPv4', purge: true, ignore_foreign: input) }.to raise_error(Puppet::Error)
        end
      end
    end
  end
end
