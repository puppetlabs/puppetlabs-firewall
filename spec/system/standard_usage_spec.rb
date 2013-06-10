require 'spec_helper_system'

# Some tests for the standard recommended usage
describe 'standard usage tests:' do
  context 'standard 1' do
    pp = <<-EOS
      class my_fw::pre {
        Firewall {
          require => undef,
        }

        # Default firewall rules
        firewall { '000 accept all icmp':
          proto   => 'icmp',
          action  => 'accept',
        }->
        firewall { '001 accept all to lo interface':
          proto   => 'all',
          iniface => 'lo',
          action  => 'accept',
        }->
        firewall { '002 accept related established rules':
          proto   => 'all',
          state   => ['RELATED', 'ESTABLISHED'],
          action  => 'accept',
        }
      }
      class my_fw::post {
        firewall { '999 drop all':
          proto   => 'all',
          action  => 'drop',
          before  => undef,
        }
      }
      resources { "firewall":
        purge => true
      }
      Firewall {
        before  => Class['my_fw::post'],
        require => Class['my_fw::pre'],
      }
      class { ['my_fw::pre', 'my_fw::post']: }
      class { 'firewall': }
      firewall { '500 open up port 22':
        action => 'accept',
        proto => 'tcp',
        dport => 22,
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
end
