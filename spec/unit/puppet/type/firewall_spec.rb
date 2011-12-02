#!/usr/bin/env rspec

require 'spec_helper'

firewall = Puppet::Type.type(:firewall)

describe firewall do
  before :each do
    @class = firewall
    @provider = stub 'provider'
    @provider.stubs(:name).returns(:iptables)
    Puppet::Type::Firewall.stubs(:defaultprovider).returns @provider

    @resource = @class.new({:name  => '000 test foo'})
  end

  it 'should have :name be its namevar' do
    @class.key_attributes.should == [:name]
  end

  describe ':name' do
    it 'should accept a name' do
      @resource[:name] = '000-test-foo'
      @resource[:name].should == '000-test-foo'
    end

    it 'should not accept a name with non-ASCII chars' do
      lambda { @resource[:name] = '%*#^(#$' }.should raise_error(Puppet::Error)
    end
  end

  describe ':action' do
    it "should have no default" do
      res = @class.new(:name => "000 test")
      res.parameters[:action].should == nil
    end
 
    [:accept, :drop, :reject].each do |action|
      it "should accept value #{action}" do
        @resource[:action] = action
        @resource[:action].should == action
      end
    end

    it 'should fail when value is not recognized' do
      lambda { @resource[:action] = 'not valid' }.should raise_error(Puppet::Error)
    end
  end

  describe ':chain' do
    [:INPUT, :FORWARD, :OUTPUT, :PREROUTING, :POSTROUTING].each do |chain|
      it "should accept chain value #{chain}" do
        @resource[:chain] = chain
        @resource[:chain].should == chain
      end
    end

    it 'should fail when the chain value is not recognized' do
      lambda { @resource[:chain] = 'not valid' }.should raise_error(Puppet::Error)
    end
  end

  describe ':table' do
    [:nat, :mangle, :filter, :raw].each do |table|
      it "should accept table value #{table}" do
        @resource[:table] = table
        @resource[:table].should == table
      end
    end

    it "should fail when table value is not recognized" do
      lambda { @resource[:table] = 'not valid' }.should raise_error(Puppet::Error)
    end
  end

  describe ':proto' do
    [:tcp, :udp, :icmp, :esp, :ah, :vrrp, :igmp, :ipencap, :all].each do |proto|
      it "should accept proto value #{proto}" do
        @resource[:proto] = proto
        @resource[:proto].should == proto
      end
    end

    it "should fail when proto value is not recognized" do
      lambda { @resource[:proto] = 'foo' }.should raise_error(Puppet::Error)
    end
  end

  describe ':jump' do
    it "should have no default" do
      res = @class.new(:name => "000 test")
      res.parameters[:jump].should == nil
    end

    ['QUEUE', 'RETURN', 'DNAT', 'SNAT', 'LOG', 'MASQUERADE', 'REDIRECT'].each do |jump|
      it "should accept jump value #{jump}" do
        @resource[:jump] = jump
        @resource[:jump].should == jump
      end
    end

    ['ACCEPT', 'DROP', 'REJECT'].each do |jump|
      it "should now fail when value #{jump}" do
        lambda { @resource[:jump] = jump }.should raise_error(Puppet::Error)
      end
    end

    it "should fail when jump value is not recognized" do
      lambda { @resource[:jump] = '%^&*' }.should raise_error(Puppet::Error)
    end
  end

  [:source, :destination].each do |addr|
    describe addr do
      it "should accept a #{addr} as a string" do
        @resource[addr] = '127.0.0.1'
        @resource[addr].should == '127.0.0.1/32'
      end
    end
  end

  [:dport, :sport].each do |port|
    describe port do
      it "should accept a #{port} as string" do
        @resource[port] = '22'
        @resource[port].should == ['22']
      end

      it "should accept a #{port} as an array" do
        @resource[port] = ['22','23']
        @resource[port].should == ['22','23']
      end

      it "should accept a #{port} as a hyphen separated range" do
        @resource[port] = ['22-1000']
        @resource[port].should == ['22-1000']
      end

      it "should accept a #{port} as a combination of arrays of single and " \
        "hyphen separated ranges" do

        @resource[port] = ['22-1000','33','3000-4000']
        @resource[port].should == ['22-1000','33','3000-4000']
      end

      it "should convert a port name for #{port} to its number" do
        @resource[port] = 'ssh'
        @resource[port].should == ['22']
      end

      it "should not accept something invalid for #{port}" do
        expect { @resource[port] = 'something odd' }.should raise_error(Puppet::Error, /^Parameter .+ failed: Munging failed for value ".+" in class .+: no such service/)
      end

      it "should not accept something invalid in an array for #{port}" do
        expect { @resource[port] = ['something odd','something even odder'] }.should raise_error(Puppet::Error, /^Parameter .+ failed: Munging failed for value ".+" in class .+: no such service/)
      end
    end
  end

  [:iniface, :outiface].each do |iface|
    describe iface do
      it "should accept #{iface} value as a string" do
        @resource[iface] = 'eth1'
        @resource[iface].should == 'eth1'
      end
    end
  end

  [:tosource, :todest].each do |addr|
    describe addr do
      it "should accept #{addr} value as a string" do
        @resource[addr] = '127.0.0.1'
      end
    end
  end

  describe ':log_level' do
    values = {
      'panic' => '0',
      'alert' => '1',
      'crit'  => '2',
      'err'   => '3',
      'warn'  => '4',
      'warning' => '4',
      'not'  => '5',
      'notice' => '5',
      'info' => '6',
      'debug' => '7'
    }

    values.each do |k,v|
      it {
        @resource[:log_level] = k
        @resource[:log_level].should == v
      }

      it {
        @resource[:log_level] = 3
        @resource[:log_level].should == 3
      }

      it { lambda { @resource[:log_level] = 'foo' }.should raise_error(Puppet::Error) }
    end
  end

  describe ':icmp' do
    values = {
      '0' => 'echo-reply',
      '3' => 'destination-unreachable',
      '4' => 'source-quench',
      '6' => 'redirect',
      '8' => 'echo-request',
      '9' => 'router-advertisement',
      '10' => 'router-solicitation',
      '11' => 'time-exceeded',
      '12' => 'parameter-problem',
      '13' => 'timestamp-request',
      '14' => 'timestamp-reply',
      '17' => 'address-mask-request',
      '18' => 'address-mask-reply'
    }
    values.each do |k,v|
      it 'should convert icmp string to number' do
        @resource[:icmp] = v
        @resource[:icmp].should == k
      end
    end

    it 'should accept values as integers' do
      @resource[:icmp] = 9
      @resource[:icmp].should == 9
    end

    it 'should fail if icmp type is not recognized' do
      lambda { @resource[:icmp] = 'foo' }.should raise_error(Puppet::Error)
    end
  end

  describe ':state' do
    it 'should accept value as a string' do
      @resource[:state] = :INVALID
      @resource[:state].should == [:INVALID]
    end

    it 'should accept value as an array' do
      @resource[:state] = [:INVALID, :NEW]
      @resource[:state].should == [:INVALID, :NEW]
    end

    it 'should sort values alphabetically' do
      @resource[:state] = [:NEW, :ESTABLISHED]
      @resource[:state].should == [:ESTABLISHED, :NEW]
    end
  end

  describe ':burst' do
    it 'should accept numeric values' do
      @resource[:burst] = 12
      @resource[:burst].should == 12
    end

    it 'should fail if value is not numeric' do
      lambda { @resource[:burst] = 'foo' }.should raise_error(Puppet::Error)
    end
  end

  describe ':action and :jump' do
    it 'should allow only 1 to be set at a time' do
      expect { 
        @class.new(
          :name => "001-test", 
          :action => "accept", 
          :jump => "custom_chain"
        )
      }.should raise_error(Puppet::Error, /^Only one of the parameters 'action' and 'jump' can be set$/)
    end
  end
  describe ':gid and :uid' do
    it 'should allow me to set uid' do
      @resource[:uid] = 'root'
      @resource[:uid].should == ['root']
    end
    it 'should allow me to set uid as an array, breaking iptables' do
      @resource[:uid] = ['root', 'bobby']
      @resource[:uid].should == ['root', 'bobby']
    end
    it 'should allow me to set gid' do
      @resource[:gid] = 'root'
      @resource[:gid].should == ['root']
    end
    it 'should allow me to set gid as an array, breaking iptables' do
      @resource[:gid] = ['root', 'bobby']
      @resource[:gid].should == ['root', 'bobby']
    end
  end
end
