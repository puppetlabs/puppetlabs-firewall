# frozen_string_literal: true

require 'spec_helper'

RSpec.shared_examples 'ensures iptables service' do
  context 'with default' do
    it {
      expect(subject).to contain_service('iptables').with(
        ensure: 'running',
        enable: 'true',
      )
    }
  end

  context 'with ensure => stopped' do
    let(:params) { { ensure: 'stopped' } }

    it {
      expect(subject).to contain_service('iptables').with(
        ensure: 'stopped',
      )
    }
  end

  context 'with enable => false' do
    let(:params) { { enable: 'false' } }

    it {
      expect(subject).to contain_service('iptables').with(
        enable: 'false',
      )
    }
  end
end

describe 'firewall::linux::redhat', type: :class do
  ['RedHat', 'CentOS', 'Fedora', 'AlmaLinux'].each do |os|
    releases = ((os == 'Fedora') ? ['36'] : ['7.0.1406'])
    nftablesreleases = ((os == 'Fedora') ? [] : ['8.0'])

    releases.each do |osrel|
      context "with os #{os} and osrel #{osrel}" do
        let(:facts) do
          {
            kernel: 'Linux',
            os: {
              name: os,
              release: { full: osrel },
              family: 'RedHat',
              selinux: { enabled: false }
            },
            puppetversion: Puppet.version
          }
        end

        it {
          expect(subject).to contain_service('iptables').with(
            ensure: 'running',
            enable: 'true',
          )
        }

        it {
          expect(subject).to contain_service('ip6tables').with(
            ensure: 'running',
            enable: 'true',
          )
        }

        it {
          expect(subject).to contain_file('/etc/sysconfig/iptables')
          expect(subject).to contain_file('/etc/sysconfig/ip6tables')
        }

        context 'with ensure => stopped' do
          let(:params) { { ensure: 'stopped' } }

          it {
            expect(subject).to contain_service('iptables').with(
              ensure: 'stopped',
            )
          }
        end

        context 'with ensure_v6 => stopped' do
          let(:params) { { ensure_v6: 'stopped' } }

          it {
            expect(subject).to contain_service('ip6tables').with(
              ensure: 'stopped',
            )
          }
        end

        context 'with enable => false' do
          let(:params) { { enable: 'false' } }

          it {
            expect(subject).to contain_service('iptables').with(
              enable: 'false',
            )
          }
        end

        context 'with enable_v6 => false' do
          let(:params) { { enable_v6: 'false' } }

          it {
            expect(subject).to contain_service('ip6tables').with(
              enable: 'false',
            )
          }
        end

        it {
          expect(subject).to contain_service('firewalld').with(
            ensure: 'stopped',
            enable: false,
            before: ['Package[iptables-services]', 'Service[iptables]'],
          )
        }

        it {
          expect(subject).to contain_package('iptables-services').with(
            ensure: 'installed',
            before: 'Service[iptables]',
          )
        }

        it_behaves_like 'ensures iptables service'
      end
    end

    nftablesreleases.each do |osrel|
      context "with os #{os} and osrel #{osrel}" do
        let(:facts) do
          {
            kernel: 'Linux',
            os: {
              name: os,
              release: { full: osrel },
              family: 'RedHat',
              selinux: { enabled: false }
            },
            puppetversion: Puppet.version
          }
        end

        it {
          expect(subject).to contain_service('nftables').with(
            ensure: 'running',
            enable: 'true',
          )
          expect(subject).to contain_service('iptables').with(
            ensure: 'running',
            enable: 'true',
          )
        }

        context 'with ensure => stopped' do
          let(:params) { { ensure: 'stopped' } }

          it {
            expect(subject).to contain_service('nftables').with(
              ensure: 'stopped',
            )
            expect(subject).to contain_service('iptables').with(
              ensure: 'stopped',
            )
          }
        end

        context 'with enable => false' do
          let(:params) { { enable: 'false' } }

          it {
            expect(subject).to contain_service('nftables').with(
              enable: 'false',
            )
            expect(subject).to contain_service('iptables').with(
              enable: 'false',
            )
          }
        end

        it {
          expect(subject).to contain_service('firewalld').with(
            ensure: 'stopped',
            enable: false,
            before: ['Package[iptables-services]', 'Package[nftables]', 'Service[iptables]', 'Service[nftables]'],
          )
        }

        it {
          expect(subject).to contain_package('iptables-services').with(
            ensure: 'installed',
            before: ['Service[iptables]', 'Service[nftables]'],
          )
        }

        it {
          expect(subject).to contain_package('nftables').with(
            ensure: 'installed',
            before: ['Service[iptables]', 'Service[nftables]'],
          )
        }

        it {
          expect(subject).not_to contain_file('/etc/sysconfig/nftables')
        }
      end
    end
  end
end
