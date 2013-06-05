require 'spec_helper_system'

describe "firewall class:" do
  it 'should run successfully' do
    pp = "class { 'firewall': }"

    puppet_apply(pp) do |r|
      r.stderr.should be_empty
      r.exit_code.should_not == 1
    end

    puppet_apply(pp) do |r|
      r.stderr.should be_empty
      r.exit_code.should be_zero
    end
  end

  it 'ensure => stopped:' do
    pp = <<-EOS
      class { 'firewall':
        ensure => stopped,
      }
    EOS

    puppet_apply(pp) do |r|
      r.stderr.should be_empty
      r.exit_code.should_not == 1
    end

    puppet_apply(pp) do |r|
      r.stderr.should be_empty
      r.exit_code.should be_zero
    end
  end

  it 'ensure => running:' do
    pp = <<-EOS
      class { 'firewall':
        ensure => running,
      }
    EOS

    puppet_apply(pp) do |r|
      r.stderr.should be_empty
      r.exit_code.should_not == 1
    end

    puppet_apply(pp) do |r|
      r.stderr.should be_empty
      r.exit_code.should be_zero
    end
  end
end
