# frozen_string_literal: true

require 'spec_helper_acceptance'

# Some tests for the standard recommended usage
describe 'standard usage tests' do
  pp = <<-PUPPETCODE
      class my_fw::pre {
        Firewall {
          require => undef,
        }

        # Default firewall rules
        firewall { '000 accept all icmp':
          proto   => 'icmp',
          jump    => 'ACCEPT',
        }->
        firewall { '001 accept all to lo interface':
          proto   => 'all',
          iniface => 'lo',
          jump    => 'ACCEPT',
        }->
        firewall { "0002 reject local traffic not on loopback interface":
          iniface     => '! lo',
          destination => '127.0.0.0/8',
          jump        => 'REJECT',
        }->
        firewall { '003 accept related established rules':
          proto   => 'all',
          ctstate => ['RELATED', 'ESTABLISHED'],
          jump    => 'ACCEPT',
        }
      }
      class my_fw::post {
        firewall { '999 drop all':
          proto   => 'all',
          jump    => 'DROP',
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
        jump  => 'ACCEPT',
        proto => 'tcp',
        dport => '22',
      }
  PUPPETCODE
  it 'applies twice' do
    # Run it twice and test for idempotency
    idempotent_apply(pp)
  end
end
