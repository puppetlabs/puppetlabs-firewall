require 'spec_helper'

describe Puppet::Type.type(:firewall) do
  before :each do
    @resource = Puppet::Type.type(:firewall).new({
      :name => 'new_resource',
      :chain => 'INPUT',
      :jump => 'ACCEPT'
    })
  end

  describe ':name' do
    it 'should accept a name' do
      @resource[:name] = '000-test-foo'
      @resource[:name].should == '000-test-foo'
    end

    it 'should not accept a name with non-ASCII chars' do
      @resource[:name] = '%*#^(#$'
      @resource[:name].should raise_error(Puppet::Type::Firewall)
    end
  end

  describe ':chain' do
    [:INPUT, :FORWARD, :OUTPUT, :PREROUTING, :POSTROUTING].each do |chain|
      it "should accept chain value #{chain}" do
        @resource[:chain] = chain
        @resource[:chain].should == chain
      end
    end
  end

  describe ':table' do
    [:nat, :mangle, :filter, :raw].each do |table|
      it "should accept table value #{table}" do
        @resource[:table] = table
        @resource[:table].should == table
      end
    end
  end

  describe ':dport/sport' do
    [:dport, :sport].each do |port|
      it "should accept a #{port} as string" do
        @resource[port] = '22'
        @resource[port].should == [22]
      end

      it "should accept a #{port} as an array" do
        @resource[port] = ['22','23']
        @resource[port].should == [22,23]
      end
    end
  end
end
