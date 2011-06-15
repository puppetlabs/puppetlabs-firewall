require 'spec_helper'

describe Puppet::Type.type(:firewall) do
  before :each do
    @resource = Puppet::Type.type(:firewall).new({
      :name => 'new_resource',
      :chain => 'INPUT',
      :jump => 'ACCEPT'
    })
  end

  it 'should accept a name' do
    @resource[:name] = '000-test-foo'
    @resource[:name].should == '000-test-foo'
  end

  it 'should accept a dport' do
    @resource[:dport] = '22'
    @resource[:dport].should == [22]
  end
end
