require 'spec_helper'

RSpec.shared_examples 'ensures iptables service' do
  context 'with default' do
    it {
      is_expected.to contain_service('iptables').with(
        ensure: 'running',
        enable: 'true',
      )
    }
  end

  context 'with ensure => stopped' do
    let(:params) { { ensure: 'stopped' } }

    it {
      is_expected.to contain_service('iptables').with(
        ensure: 'stopped',
      )
    }
  end

  context 'with enable => false' do
    let(:params) { { enable: 'false' } }

    it {
      is_expected.to contain_service('iptables').with(
        enable: 'false',
      )
    }
  end
end

describe 'firewall::linux::redhat', type: :class do
  ['RedHat', 'CentOS', 'Fedora'].each do |os|
    oldreleases = ((os == 'Fedora') ? ['14'] : ['6.5'])
    newreleases = ((os == 'Fedora') ? ['15', 'Rawhide'] : ['7.0.1406'])
    nftablesreleases = ((os == 'Fedora') ? [] : ['8.0'])

    oldreleases.each do |osrel|
      context "os #{os} and osrel #{osrel}" do
        let(:facts) do
          {
            operatingsystem: os,
            operatingsystemrelease: osrel,
            osfamily: 'RedHat',
            selinux: false,
            puppetversion: Puppet.version,
          }
        end

        it { is_expected.not_to contain_service('firewalld') }
        it { is_expected.not_to contain_package('iptables-services') }
        it {
          is_expected.to contain_file('/etc/sysconfig/iptables')
          is_expected.to contain_file('/etc/sysconfig/ip6tables')
        }

        it_behaves_like 'ensures iptables service'
      end
    end

    newreleases.each do |osrel|
      context "os #{os} and osrel #{osrel}" do
        let(:facts) do
          {
            operatingsystem: os,
            operatingsystemrelease: osrel,
            osfamily: 'RedHat',
            selinux: false,
            puppetversion: Puppet.version,
          }
        end

        it {
          is_expected.to contain_service('iptables').with(
            ensure: 'running',
            enable: 'true',
          )
        }
        it {
          is_expected.to contain_service('ip6tables').with(
            ensure: 'running',
            enable: 'true',
          )
        }
        it {
          is_expected.to contain_file('/etc/sysconfig/iptables')
          is_expected.to contain_file('/etc/sysconfig/ip6tables')
        }

        context 'with ensure => stopped' do
          let(:params) { { ensure: 'stopped' } }

          it {
            is_expected.to contain_service('iptables').with(
              ensure: 'stopped',
            )
          }
        end

        context 'with ensure_v6 => stopped' do
          let(:params) { { ensure_v6: 'stopped' } }

          it {
            is_expected.to contain_service('ip6tables').with(
              ensure: 'stopped',
            )
          }
        end

        context 'with enable => false' do
          let(:params) { { enable: 'false' } }

          it {
            is_expected.to contain_service('iptables').with(
              enable: 'false',
            )
          }
        end

        context 'with enable_v6 => false' do
          let(:params) { { enable_v6: 'false' } }

          it {
            is_expected.to contain_service('ip6tables').with(
              enable: 'false',
            )
          }
        end

        it {
          is_expected.to contain_service('firewalld')
            .with(
              ensure: 'stopped',
              enable: false,
            )
            .that_comes_before('Package[iptables-services]')
            .that_comes_before('Service[iptables]')
        }

        it {
          is_expected.to contain_package('iptables-services').with(
            ensure: 'present',
            before: 'Service[iptables]',
          )
        }

        it_behaves_like 'ensures iptables service'
      end
    end

    nftablesreleases.each do |osrel|
      context "os #{os} and osrel #{osrel}" do
        let(:facts) do
          {
            operatingsystem: os,
            operatingsystemrelease: osrel,
            osfamily: 'RedHat',
            selinux: false,
            puppetversion: Puppet.version,
          }
        end

        it {
          is_expected.to contain_service('nftables').with(
            ensure: 'running',
            enable: 'true',
          )
          is_expected.not_to contain_service('iptables')
        }

        context 'with ensure => stopped' do
          let(:params) { { ensure: 'stopped' } }

          it {
            is_expected.to contain_service('nftables').with(
              ensure: 'stopped',
            )
          }
        end

        context 'with enable => false' do
          let(:params) { { enable: 'false' } }

          it {
            is_expected.to contain_service('nftables').with(
              enable: 'false',
            )
          }
        end

        it {
          is_expected.to contain_service('firewalld').with(
            ensure: 'stopped',
            enable: false,
            before: ['Package[nftables]', 'Service[nftables]'],
          )
        }

        it {
          is_expected.to contain_package('nftables').with(
            ensure: 'present',
            before: 'Service[nftables]',
          )
        }

        it {
          is_expected.not_to contain_file('/etc/sysconfig/nftables')
        }
      end
    end
  end
end
