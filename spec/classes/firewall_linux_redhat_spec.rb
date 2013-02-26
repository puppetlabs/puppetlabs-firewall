require 'spec_helper'

describe 'firewall::linux::redhat' do
  it { should contain_service('iptables').with(
    :ensure => 'running',
    :enable => 'true'
  )}
end
