require 'spec_helper'

describe 'firewall::linux::redhat', :type => :class do
  %w{RedHat CentOS Fedora}.each do |os|
    oldreleases = (os == 'Fedora' ? ['14'] : ['6.5'])
    newreleases = (os == 'Fedora' ? ['15','Rawhide'] : ['7.0.1406'])

    oldreleases.each do |osrel|
      context "os #{os} and osrel #{osrel}" do
        let(:facts) {{
          :operatingsystem        => os,
          :operatingsystemrelease => osrel
        }}

        it { should_not contain_package('firewalld') }
        it { should_not contain_package('iptables-services') }
      end
    end

    newreleases.each do |osrel|
      context "os #{os} and osrel #{osrel}" do
        let(:facts) {{
          :operatingsystem        => os,
          :operatingsystemrelease => osrel
        }}

        it { should contain_package('firewalld').with(
          :ensure => 'purged',
          :before => 'Package[iptables-services]'
        )}

        it { should contain_package('iptables-services').with(
          :ensure => 'present',
          :before => 'Service[iptables]'
        )}
      end
    end

    describe 'ensure' do
      context 'default' do
        it { should contain_service('iptables').with(
          :ensure => 'running',
          :enable => 'true'
        )}
      end
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
    end
  end
end
