#!/usr/bin/env rspec

require 'spec_helper'

firewallchain = Puppet::Type.type(:firewallchain)

describe firewallchain do
  before :each do
    @class = firewallchain
    @provider = stub 'provider'
    @provider.stubs(:name).returns(:iptables_chain)
    Puppet::Type::Firewallchain.stubs(:defaultprovider).returns @provider
    @resource = @class.new({:name => ':INPUT:', :policy => :accept })
  end

  it 'should have :name be its namevar' do
    @class.key_attributes.should == [:name]
  end

  describe ':name' do
    {'' => ['INPUT','OUTPUT','FORWARD'],
     'NAT' => ['PREROUTING', 'POSTROUTING', 'OUTPUT'],
     'MANGLE' => [ 'PREROUTING', 'POSTROUTING', 'INPUT', 'FORWARD', 'OUTPUT' ],
     'FILTER' => ['INPUT','OUTPUT','FORWARD'],
     'RAW' => [ 'PREROUTING', 'OUTPUT'],
     'BROUTE' => ['BROUTING']
    }.each_pair do |table, allowedinternalchains|
      ['', 'IPv4', 'IPv6', 'IP', 'ethernet'].each do |protocol|
        [ 'test', '$5()*&%\'"^$09):' ].each do |chainname|
          name = "#{table}:#{chainname}:#{protocol}"
          if table == 'NAT' && ['IPv6','','IP'].include?(protocol)
            it "should fail #{name}" do
              lambda { @resource[:name] = name }.should raise_error(Puppet::Error)
            end
          elsif protocol != 'ethernet' && table == 'BROUTE'
            it "should fail #{name}" do
              lambda { @resource[:name] = name }.should raise_error(Puppet::Error)
            end
          else
            it "should accept name #{name}" do
              @resource[:name] = name
              @resource[:name].should == name
            end
          end
        end # chainname
      end # protocol

      [ 'PREROUTING', 'POSTROUTING', 'BROUTING', 'INPUT', 'FORWARD', 'OUTPUT' ].each do |internalchain|
        name = table + ':' + internalchain + ':'
        if internalchain == 'BROUTING'
          name += 'ethernet'
        elsif table == 'NAT'
          name += 'IPv4'
        end
        if allowedinternalchains.include? internalchain
          it "should allow #{name}" do
            @resource[:name] = name
            @resource[:name].should == name
          end
        else
          it "should fail #{name}" do
            lambda { @resource[:name] = name }.should raise_error(Puppet::Error)
          end
        end
      end # internalchain

    end # table, allowedinternalchainnames

    it 'should fail with invalid table names' do
      lambda { @resource[:name] = 'wrongtablename:test:' }.should raise_error(Puppet::Error)
    end

    it 'should fail with invalid protocols names' do
      lambda { @resource[:name] = ':test:IPv5' }.should raise_error(Puppet::Error)
    end

  end

  describe ':policy' do
 
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
        lambda { @class.new({:name => ':testchain:', :policy => policy }) }.should raise_error(Puppet::Error)
      end
      it "non-inbuilt chains can accept policies on protocol = ethernet (policy #{policy})" do
        @class.new({:name => ':testchain:ethernet', :policy => policy }).should be_instance_of(@provider)
      end
    end

  end

end
