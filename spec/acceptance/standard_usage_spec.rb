require 'spec_helper_acceptance'

# Some tests for the standard recommended usage
describe 'standard usage tests:', :unless => UNSUPPORTED_PLATFORMS.include?(fact('osfamily')) do
  it 'applies twice' do
    pp = <<-EOS
      class my_fw::pre {
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
          ctstate => ['RELATED', 'ESTABLISHED'],
          action  => 'accept',
        }
      }
      class my_fw::post {
        firewall { '999 drop all':
          proto   => 'all',
          action  => 'drop',
        }
      }
      resources { "firewall":
        purge => true
      }
      class { ['my_fw::pre', 'my_fw::post']: }
      class { 'firewall': }
      firewall { '500 open up port 22':
        action  => 'accept',
        proto   => 'tcp',
        dport   => 22,
        before  => Class['my_fw::post'],
        require => Class['my_fw::pre'],
      }
    EOS

    # Run it twice and test for idempotency
    apply_manifest(pp, :catch_failures => true)
    apply_manifest(pp, :catch_changes  => true)
  end
end
