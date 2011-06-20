require 'spec_helper'

describe 'iptables provider' do
  before :each do
    @provider = Puppet::Type.type(:firewall).provider(:iptables)
  end
  
  it 'should be able to get a list of existing rules' do
    @provider.instances.each do |rule|
      rule.should be_instance_of(@provider)
      rule.properties[:provider].to_s.should == @provider.name.to_s
    end
  end

  describe 'when converting rules to resources' do
    before :each do
      @resource = @provider.rule_to_hash('-A INPUT -p tcp -m multiport --dports 7061,7062 -m comment --comment "000 allow foo" -j ACCEPT', 'filter', 0)
    end

    [:name, :table, :chain, :proto, :jump].each do |param|
      it "#{param} should be a string" do
        @resource[param].class.should == String
      end
    end

    [:dport, :sport, :source, :destination].each do |param|
      it "#{param} should be an array" do
        @resource[param].class.should == Array
      end
    end
  end

  describe 'when modifying resources' do
    before :each do
      @resource = @provider.new(Puppet::Type::Firewall.new({
        :name => '000-test-foo',
        :chain => 'INPUT',
        :jump => 'ACCEPT'
      }))
    end
  end
end
