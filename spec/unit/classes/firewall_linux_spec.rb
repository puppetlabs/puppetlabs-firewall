# frozen_string_literal: true

require 'spec_helper'

describe 'firewall::linux', type: :class do
  ['RedHat', 'CentOS'].each do |os|
    context "with Redhat Like: operatingsystem => #{os}" do
      releases = ['7', '8']
      releases.each do |osrel|
        context "when operatingsystemrelease => #{osrel}" do
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

          it { is_expected.to contain_class('firewall::linux::redhat').with_require('Package[iptables]') }
          it { is_expected.to contain_package('iptables').with_ensure('installed') }
        end
      end
    end
  end

  ['Debian', 'Ubuntu'].each do |os|
    context "with Debian Like: operatingsystem => #{os}" do
      releases = ((os == 'Debian') ? ['10', '11'] : ['20.04', '22.04'])
      releases.each do |osrel|
        let(:facts) do
          {
            kernel: 'Linux',
            os: {
              name: os,
              release: { full: osrel },
              family: 'Debian',
              selinux: { enabled: false }
            },
            puppetversion: Puppet.version
          }
        end

        it { is_expected.to contain_class('firewall::linux::debian').with_require('Package[iptables]') }
        it { is_expected.to contain_package('iptables').with_ensure('installed') }
      end
    end
  end
end
