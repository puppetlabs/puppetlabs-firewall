require 'spec_helper'

describe 'iptables provider detection' do
  before :each do
    require 'puppet/provider/confine/exists'
    @exists = Puppet::Provider::Confine::Exists

    # Reset the default provider
    Puppet::Type.type(:firewall).defaultprovider = nil
  end

  it "should default to iptables provider if /sbin/iptables[-save] exists" do
    # Stub lookup for /sbin/iptables & /sbin/iptables-save
    @exists.any_instance.stubs(:which).with("/sbin/iptables").
      returns "/sbin/iptables"
    @exists.any_instance.stubs(:which).with("/sbin/iptables-save").
      returns "/sbin/iptables-save"

    # Every other command should return false so we don't pick up any
    # other providers
    @exists.any_instance.stubs(:which).with() { |value|
      ! ["/sbin/iptables","/sbin/iptables-save"].include?(value)
    }.returns false

    # Create a resource instance and make sure the provider is iptables
    resource = Puppet::Type.type(:firewall).new({
      :name => '000 test foo',
    })
    resource.provider.class.to_s.should == "Puppet::Type::Firewall::ProviderIptables"
  end

  it "should raise a default provider error when there are no commands" do
    # Stub all commands lookups so they return nothing 
    @exists.any_instance.stubs(:which).returns false

    # Instantiate a resource instance and make sure it raises an exception
    lambda { resource = Puppet::Type.type(:firewall).new({ 
      :name => '000 test foo' }) }.should raise_error(Puppet::DevError, 
      "Could not find a default provider for firewall")
  end

end

describe 'iptables provider' do
  before :each do
    @provider = Puppet::Type.type(:firewall).provider(:iptables)
    Puppet::Type::Firewall.stubs(:defaultprovider).returns @provider
    @provider.stubs(:command).with(:iptables_save).returns "/sbin/iptables-save"
    @resource = Puppet::Type.type(:firewall).new({
      :name  => '000 test foo',
      :chain => 'INPUT',
      :jump  => 'ACCEPT'
    })
  end
  
  it 'should be able to get a list of existing rules' do
    # Pretend to return nil from iptables
    @provider.expects(:execute).with(['/sbin/iptables-save']).returns("")

    @provider.instances.each do |rule|
      rule.should be_instance_of(@provider)
      rule.properties[:provider].to_s.should == @provider.name.to_s
    end
  end

  describe 'when converting rules to resources' do
    before :each do
      @resource = @provider.rule_to_hash('-A INPUT -s 1.1.1.1 -d 1.1.1.1 -p tcp -m multiport --dports 7061,7062 -m multiport --sports 7061,7062 -m comment --comment "000 allow foo" -j ACCEPT', 'filter', 0)
    end

    [:name, :table, :chain, :proto, :jump, :source, :destination].each do |param|
      it "#{param} should be a string" do
        @resource[param].class.should == String
      end
    end

    [:dport, :sport].each do |param|
      it "#{param} should be an array" do
        @resource[param].class.should == Array
      end
    end
  end

  describe 'when modifying resources' do
    before :each do
      @instance = @provider.new(@resource)
      @provider.expects(:execute).with(['/sbin/iptables-save']).returns("")
    end

    it 'should do something' do
      @instance.insert_args.class.should == Array
    end
  end
end
