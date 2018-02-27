require 'spec_helper'

RSpec.shared_examples 'ensures iptables service' do
  context 'with default' do
    it {
      is_expected.to contain_service('firewall').with(
        ensure: 'running',
        enable: 'true',
      )
    }
  end

  context 'with ensure => stopped' do
    let(:params) { { ensure: 'stopped' } }

    it {
      is_expected.to contain_service('firewall').with(
        ensure: 'stopped',
      )
    }
  end

  context 'with enable => false' do
    let(:params) { { enable: 'false' } }

    it {
      is_expected.to contain_service('firewall').with(
        enable: 'false',
      )
    }
  end
end

describe 'firewall::linux::redhat', type: :class do
  %w[RedHat CentOS Fedora].each do |os|
    oldreleases = ((os == 'Fedora') ? ['14'] : ['6.5'])
    newreleases = ((os == 'Fedora') ? %w[15 Rawhide] : ['7.0.1406'])

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
          is_expected.to contain_service('firewall').with(
            ensure: 'running',
            enable: 'true',
          )
        }
        it {
          is_expected.to contain_service('firewall6').with(
            ensure: 'running',
            enable: 'true',
          )
        }

        context 'with ensure => stopped' do
          let(:params) { { ensure: 'stopped' } }

          it {
            is_expected.to contain_service('firewall').with(
              ensure: 'stopped',
            )
          }
        end

        context 'with ensure_v6 => stopped' do
          let(:params) { { ensure_v6: 'stopped' } }

          it {
            is_expected.to contain_service('firewall6').with(
              ensure: 'stopped',
            )
          }
        end

        context 'with enable => false' do
          let(:params) { { enable: 'false' } }

          it {
            is_expected.to contain_service('firewall').with(
              enable: 'false',
            )
          }
        end

        context 'with enable_v6 => false' do
          let(:params) { { enable_v6: 'false' } }

          it {
            is_expected.to contain_service('firewall6').with(
              enable: 'false',
            )
          }
        end

        it {
          is_expected.to contain_service('firewall').with(
            ensure: 'stopped',
            enable: false,
            before: ['Package[iptables-services]', 'Service[firewall]'],
          )
        }

        it {
          is_expected.to contain_package('iptables-services').with(
            ensure: 'present',
            before: 'Service[firewall]',
          )
        }

        it_behaves_like 'ensures iptables service'
      end
    end
  end
end
