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
      lambda { @resource[:name] = '%*#^(#$' }.should raise_error(Puppet::Error)
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
      lambda { @resource[:chain] = 'foo' }.should raise_error(Puppet::Error)
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
      lambda { @resource[:table] = 'foo' }.should raise_error(Puppet::Error)
    end
  end

  describe ':proto' do
    [:tcp, :udp, :icmp, :esp, :ah, :vrrp, :igmp, :all].each do |proto|
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
    [:ACCEPT, :DROP, :QUEUE, :RETURN, :REJECT, :DNAT, :SNAT, :LOG, :MASQUERADE, :REDIRECT].each do |jump|
      it "should accept jump value #{jump}" do
        @resource[:jump] = jump
        @resource[:jump].should == jump
      end
    end

    it "should fail when jump value is not recognized" do
      lambda { @resource[:proto] = 'jump' }.should raise_error(Puppet::Error)
    end
  end

  describe ':source/:destination' do
    [:source, :destination].each do |addr|
      it "should accept a #{addr} as a string" do
        @resource[addr] = '127.0.0.1'
        @resource[addr].should == ['127.0.0.1']
      end

      it "should accept a #{addr} as an array" do
        @resource[addr] = ['127.0.0.1', '4.2.2.2']
        @resource[addr].should == ['127.0.0.1', '4.2.2.2']
      end
    end
  end

  describe ':dport/:sport' do
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
