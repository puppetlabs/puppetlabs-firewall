require 'spec_helper_acceptance'

describe 'firewall class' do
  it 'runs successfully' do
    pp = "class { 'firewall': }"
    expect(idempotent_apply(pp).exit_code).to be_zero
  end

  it 'ensure => stopped:' do
    pp = "class { 'firewall': ensure => stopped }"
    expect(idempotent_apply(pp).exit_code).to be_zero
  end

  it 'ensure => running:' do
    pp = "class { 'firewall': ensure => running }"
    expect(idempotent_apply(pp).exit_code).to be_zero
  end
end
