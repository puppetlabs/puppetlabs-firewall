require 'spec_helper'

describe 'firewall', :type => :class do

  on_supported_os.each do |os, facts|
    context "on #{os}" do
      let(:facts) do
        facts
      end

      context 'without params' do
        it { should contain_package('iptables').with_ensure('present') }
        it { should contain_class('firewall::linux').with_ensure('running') }

        case facts[:osfamily]
        when 'ArchLinux'
          it { should contain_service('iptables').with(
            :ensure   => 'running',
            :enable   => 'true'
          )}
          it { should contain_service('ip6tables').with(
            :ensure   => 'running',
            :enable   => 'true'
          )}
        when 'Debian'
          it { should contain_class('firewall::linux::debian').with_require('Package[iptables]') }
          case facts[:operatingsystem]
          when 'Debian'
            case facts[:operatingsystemmajrelease]
            when '7'
              it { should contain_package('iptables-persistent').with(
                :ensure => 'present'
              )}
              it { should contain_service('iptables-persistent').with(
                :ensure   => nil,
                :enable   => 'true',
                :require  => 'Package[iptables-persistent]'
              )}
            when '8'
              it { should contain_package('netfilter-persistent').with(
                :ensure => 'present'
              )}
              it { should contain_service('netfilter-persistent').with(
                :ensure   => nil,
                :enable   => 'true',
                :require  => 'Package[netfilter-persistent]'
              )}
            end
          end
        when 'RedHat'
          it { should contain_class('firewall::linux::redhat').with_require('Package[iptables]') }
          if facts[:operatingsystemmajrelease].to_i < 7 or (facts[:operatingsystem] == 'Fedora' and facts[:operatingsystemmajrelease].to_i < 15)
            it { should_not contain_service('firewalld') }
            it { should_not contain_package('iptables-services') }
          else
            it { should contain_service('firewalld').with(
              :ensure => 'stopped',
              :enable => false,
              :before => 'Package[iptables-services]'
            )}

            it { should contain_package('iptables-services').with(
              :ensure => 'present',
              :before => 'Service[iptables]'
            )}
          end
          it { should contain_service('iptables').with(
            :ensure => 'running',
            :enable => 'true'
          )}
        end
      end

      context 'with ensure => stopped' do
        let(:params) {{ :ensure => 'stopped' }}
        it { should contain_class('firewall::linux').with_ensure('stopped') }
        case facts[:osfamily]
        when 'ArchLinux'
          it { should contain_service('iptables').with(
            :ensure   => 'stopped'
          )}
          it { should contain_service('ip6tables').with(
            :ensure   => 'stopped'
          )}
        when 'Debian'
          case facts[:operatingsystem]
          when 'Debian'
            case facts[:operatingsystemmajrelease]
            when '7'
              it { should contain_service('iptables-persistent').with(
                :enable   => 'false'
              )}
            when '8'
              it { should contain_service('netfilter-persistent').with(
                :enable   => 'false'
              )}
            end
          end
        when 'RedHat'
          it { should contain_service('iptables').with({
            :ensure => 'stopped',
            :enable => 'false'
          })}
        end
      end

      context 'with ensure => test' do
        let(:params) {{ :ensure => 'test' }}
        it { expect { should contain_class('firewall::linux') }.to raise_error(Puppet::Error) }
      end
    end
  end

  context 'kernel => Windows' do
    let(:facts) {{ :kernel => 'Windows' }}
    it { expect { should contain_class('firewall::linux') }.to raise_error(Puppet::Error) }
  end

  context 'kernel => SunOS' do
    let(:facts) {{ :kernel => 'SunOS' }}
    it { expect { should contain_class('firewall::linux') }.to raise_error(Puppet::Error) }
  end

  context 'kernel => Darwin' do
    let(:facts) {{ :kernel => 'Darwin' }}
    it { expect { should contain_class('firewall::linux') }.to raise_error(Puppet::Error) }
  end

end
