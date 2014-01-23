require 'spec_helper_system'

describe 'puppet resource firewallchain command:' do
  before :all do
    iptables_flush_all_tables
  end
  context 'creating firewall chains:' do
    pp = <<-EOS
      firewallchain { 'MY_CHAIN:filter:IPv4':
        ensure  => present,
      }
    EOS
    context puppet_apply(pp) do
      its(:stderr) { should be_empty }
      its(:exit_code) { should_not == 1 }
      its(:refresh) { should be_nil }
      its(:stderr) { should be_empty }
      its(:exit_code) { should be_zero }
    end
  end
  context 'adding a firewall rule to a chain:' do
    pp = <<-EOS
      firewall { '100 my rule':
        chain   => 'MY_CHAIN',
        action  => 'accept',
        proto   => 'tcp',
        dport   => 5000,
      }
    EOS
    context puppet_apply(pp) do
      its(:stderr) { should be_empty }
      its(:exit_code) { should_not == 1 }
      its(:refresh) { should be_nil }
      its(:stderr) { should be_empty }
      its(:exit_code) { should be_zero }
    end
  end
  context 'not purge firewallchain chains:' do
    it 'does not purge the rule' do
      pp = <<-EOS
        firewallchain { 'MY_CHAIN:filter:IPv4':
          ensure  => present,
          purge   => false,
          before  => Resources['firewall'],
        }
        resources { 'firewall':
          purge => true,
        }
      EOS
      puppet_apply(pp) do |r|
        r.stdout.should_not =~ /removed/
        r.stderr.should be_empty
        r.exit_code.should be_zero

        r.refresh.should be_nil
        r.stderr.should be_empty
        r.exit_code.should be_zero
      end
    end

    it 'still has the rule' do
      pp = <<-EOS
        firewall { '100 my rule':
          chain   => 'MY_CHAIN',
          action  => 'accept',
          proto   => 'tcp',
          dport   => 5000,
        }
      EOS
      puppet_apply(pp) do |r|
        r.stderr.should be_empty
        r.exit_code.should be_zero
        r.refresh.should be_nil
        r.stderr.should be_empty
        r.exit_code.should be_zero
      end
    end
  end
end
