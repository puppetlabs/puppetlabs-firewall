require 'spec_helper_system'

describe "firewall class:" do
  context 'should run successfully' do
    pp = "class { 'firewall': }"

    context puppet_apply(pp) do
      its(:stderr) { should be_empty }
      its(:exit_code) { should_not == 1 }
      its(:refresh) { should be_nil }
      its(:stderr) { should be_empty }
      its(:exit_code) { should be_zero }
    end
  end

  context 'ensure => stopped:' do
    pp = "class { 'firewall': ensure => stopped }"

    context puppet_apply(pp) do
      its(:stderr) { should be_empty }
      its(:exit_code) { should_not == 1 }
      its(:refresh) { should be_nil }
      its(:stderr) { should be_empty }
      its(:exit_code) { should be_zero }
    end
  end

  context 'ensure => running:' do
    pp = "class { 'firewall': ensure => running }"

    context puppet_apply(pp) do |r|
      its(:stderr) { should be_empty }
      its(:exit_code) { should_not == 1 }
      its(:refresh) { should be_nil }
      its(:stderr) { should be_empty }
      its(:exit_code) { should be_zero }
    end
  end
end
