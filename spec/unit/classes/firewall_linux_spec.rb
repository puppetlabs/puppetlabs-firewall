# frozen_string_literal: true

require 'spec_helper'

describe 'firewall::linux', type: :class do
  ['RedHat', 'CentOS'].each do |os|
    context "Redhat Like: operatingsystem => #{os}" do
      releases = ['6', '7', '8']
      releases.each do |osrel|
        context "operatingsystemrelease => #{osrel}" do
          let(:facts) do
            {
              kernel: 'Linux',
              operatingsystem: os,
              operatingsystemrelease: osrel,
              osfamily: 'RedHat',
              selinux: false,
              puppetversion: Puppet.version,
            }
          end

          it { is_expected.to contain_class('firewall::linux::redhat').with_require('Package[iptables]') }
          it { is_expected.to contain_package('iptables').with_ensure('installed') }
        end
      end
    end
  end

  ['Debian', 'Ubuntu'].each do |os|
    context "Debian Like: operatingsystem => #{os}" do
      releases = ((os == 'Debian') ? ['10', '11'] : ['20.04', '22.04'])
      releases.each do |osrel|
        let(:facts) do
          {
            kernel: 'Linux',
            operatingsystem: os,
            operatingsystemrelease: osrel,
            osfamily: 'Debian',
            selinux: false,
            puppetversion: Puppet.version,
          }
        end

        it { is_expected.to contain_class('firewall::linux::debian').with_require('Package[iptables]') }
        it { is_expected.to contain_package('iptables').with_ensure('installed') }
      end
    end
  end
end
