require 'spec_helper'

describe 'iptables provider' do
  before :each do
    @provider = Puppet::Type.type(:firewall).provider(:iptables)
    @resource = @provider.new(Puppet::Type::Firewall.new({
      :name => '000-test-foo',
      :chain => 'INPUT',
      :jump => 'ACCEPT'
    }))
  end
  
  it "should be able to get a list of existing rules" do
    @provider.instances.each do |rule|
      rule.should be_instance_of(@provider)
      rule.properties[:provider].to_s.should == @provider.name.to_s
    end
  end
end
