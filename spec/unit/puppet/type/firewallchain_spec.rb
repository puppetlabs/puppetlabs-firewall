#!/usr/bin/env rspec

require 'spec_helper'

firewallchain = Puppet::Type.type(:firewallchain)

describe firewallchain do
  before :each do
    @class = firewallchain
    @provider = stub 'provider'
    @provider.stubs(:name).returns(:iptables_chain)
    Puppet::Type::Firewallchain.stubs(:defaultprovider).returns @provider

    @resource = @class.new({:name => 'INPUT_IPv4', :policy => :accept })
    @resource_custom = @class.new({:name => 'testchain' })
  end

  it 'should have :name be its namevar' do
    @class.key_attributes.should == [:name]
  end

  describe ':name' do
    it 'should accept a name' do
      @resource[:name] = 'INPUT_IPv4'
      @resource[:name].should == 'INPUT_IPv4'
    end

    it 'should fail when an inbuilt chain is specified with a nonexistant table suffix' do
      lambda { @class.new({:name => 'INPUT_nontable'}) }.should raise_error(Puppet::Error)
    end

  end

  describe ':policy' do
    it "should have default table as filter " do
      res = @class.new(:name => "test")
      res.parameters[:table].should == :filter
    end
 
    [:accept, :drop, :queue, :return].each do |policy|
      it "should accept policy #{policy}" do
        @resource[:policy] = policy
        @resource[:policy].should == policy
      end
    end

    it 'should fail when value is not recognized' do
      lambda { @resource[:policy] = 'not valid' }.should raise_error(Puppet::Error)
    end

    [:accept, :drop, :queue, :return].each do |policy|
      it "non-inbuilt chains should not accept policy #{policy}" do
        lambda { @class.new({:name => 'testchain', :policy => policy }) }.should raise_error(Puppet::Error)
      end
    end

  end

  describe ':table' do
    [:nat, :mangle, :filter, :raw, :rawpost].each do |table|
      it "should accept table value #{table}" do
        @resource[:table] = table
        @resource[:table].should == table
      end
    end

    it "should fail when table value is not recognized" do
      lambda { @resource[:table] = 'not valid' }.should raise_error(Puppet::Error)
    end
  end

end
