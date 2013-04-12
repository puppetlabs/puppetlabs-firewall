require 'spec_helper'

describe 'firewall::linux::archlinux', :type => :class do
  it { should contain_service('iptables').with(
    :ensure   => 'running',
    :enable   => 'true'
  )}
  it { should contain_service('ip6tables').with(
    :ensure   => 'running',
    :enable   => 'true'
  )}
end
