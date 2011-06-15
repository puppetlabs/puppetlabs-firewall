require 'spec_helper'

provider_class = Puppet::Type.type(:firewall).provider(:iptables)
describe provider_class do
  before :each do
    @resource = Puppet::Type::Firewall.new({
      :name => '000-test-foo', 
      :chain => 'INPUT', 
      :jump => 'ACCEPT'
    })
    @provider = provider_class.new(@resource)
  end
  
  it 'should match jump' do
    @provider
  end
end
