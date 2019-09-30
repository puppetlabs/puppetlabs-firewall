require 'spec_helper_acceptance'

describe 'firewall class' do
  before(:all) do
    if os[:family] == 'ubuntu' || os[:family] == 'debian'
      update_profile_file
    end
  end

  it 'runs successfully' do
    pp = "class { 'firewall': }"
    idempotent_apply(pp)
  end

  it 'ensure => stopped:' do
    pp = "class { 'firewall': ensure => stopped }"
    idempotent_apply(pp)
  end

  it 'ensure => running:' do
    pp = "class { 'firewall': ensure => running }"
    idempotent_apply(pp)
  end
end
