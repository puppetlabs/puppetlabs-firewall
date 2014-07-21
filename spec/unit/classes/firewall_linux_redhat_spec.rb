require 'spec_helper'

describe 'firewall::linux::redhat', :type => :class do
  let(:facts) {{ :operatingsystemrelease => '6.5' }}

  it { should contain_service('iptables').with(
    :ensure => 'running',
    :enable => 'true'
  )}

  context 'ensure => stopped' do
    let(:params) {{ :ensure => 'stopped' }}
    it { should contain_service('iptables').with(
      :ensure => 'stopped'
    )}
  end

  context 'enable => false' do
    let(:params) {{ :enable => 'false' }}
    it { should contain_service('iptables').with(
      :enable => 'false'
    )}
  end

  context 'operatingsystemrelease => 7.0.1406' do
    let(:facts) {{ :operatingsystemrelease => '7.0.1406' }}
    it { should contain_package('firewalld').with(
      :ensure => 'absent',
      :before => 'Package[iptables-services]'
    )}

    it { should contain_package('iptables-services').with(
      :ensure => 'present',
      :before => 'Service[iptables]'
    )}
  end
end
