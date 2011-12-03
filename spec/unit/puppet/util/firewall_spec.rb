require 'spec_helper'

describe 'Puppet::Util::Firewall' do
  let(:resource) {
    type = Puppet::Type.type(:firewall)
    provider = stub 'provider'
    provider.stubs(:name).returns(:iptables)
    Puppet::Type::Firewall.stubs(:defaultprovider).returns(provider)
    type.new({:name => '000 test foo'})
  }

  before(:each) { resource }

  describe '#host_to_ip' do
    subject { resource }
    specify { subject.host_to_ip('puppetlabs.com').should == '96.126.112.51/32' }
    specify { subject.host_to_ip('96.126.112.51').should == '96.126.112.51/32' }
    specify { subject.host_to_ip('96.126.112.51/32').should == '96.126.112.51/32' }
    specify { subject.host_to_ip('2001:db8:85a3:0:0:8a2e:370:7334').should == '2001:db8:85a3::8a2e:370:7334/128' }
    specify { subject.host_to_ip('2001:db8:1234::/48').should == '2001:db8:1234::/48' }
  end

  describe '#icmp_name_to_number' do
    subject { resource }
    specify { subject.icmp_name_to_number('echo-reply').should == '0' }
    specify { subject.icmp_name_to_number('destination-unreachable').should == '3' }
    specify { subject.icmp_name_to_number('source-quench').should == '4' }
    specify { subject.icmp_name_to_number('redirect').should == '6' }
    specify { subject.icmp_name_to_number('echo-request').should == '8' }
    specify { subject.icmp_name_to_number('router-advertisement').should == '9' }
    specify { subject.icmp_name_to_number('router-solicitation').should == '10' }
    specify { subject.icmp_name_to_number('time-exceeded').should == '11' }
    specify { subject.icmp_name_to_number('parameter-problem').should == '12' }
    specify { subject.icmp_name_to_number('timestamp-request').should == '13' }
    specify { subject.icmp_name_to_number('timestamp-reply').should == '14' }
    specify { subject.icmp_name_to_number('address-mask-request').should == '17' }
    specify { subject.icmp_name_to_number('address-mask-reply').should == '18' }
  end

  describe '#string_to_port' do
    subject { resource }
    specify { subject.string_to_port('80').should == '80' }
    specify { subject.string_to_port('http').should == '80' }
  end
end
