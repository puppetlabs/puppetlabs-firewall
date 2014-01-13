require 'spec_helper_acceptance'

describe 'complex ruleset 1' do
  it 'applies cleanly' do
    pp = <<-EOS
      firewall { '090 forward allow local':
        chain       => 'FORWARD',
        proto       => 'all',
        source      => '10.0.0.0/8',
        destination => '10.0.0.0/8',
        action      => 'accept',
      }
      firewall { '100 forward standard allow tcp':
        chain       => 'FORWARD',
        source      => '10.0.0.0/8',
        destination => '!10.0.0.0/8',
        proto       => 'tcp',
        state       => 'NEW',
        port        => [80,443,21,20,22,53,123,43,873,25,465],
        action      => 'accept',
      }
      firewall { '100 forward standard allow udp':
        chain       => 'FORWARD',
        source      => '10.0.0.0/8',
        destination => '!10.0.0.0/8',
        proto       => 'udp',
        port        => [53,123],
        action      => 'accept',
      }
      firewall { '100 forward standard allow icmp':
        chain       => 'FORWARD',
        source      => '10.0.0.0/8',
        destination => '!10.0.0.0/8',
        proto       => 'icmp',
        action      => 'accept',
      }

      firewall { '090 ignore ipsec':
        table        => 'nat',
        chain        => 'POSTROUTING',
        outiface     => 'eth0',
        ipsec_policy => 'ipsec',
        ipsec_dir    => 'out',
        action       => 'accept',
      }
      firewall { '093 ignore 10.0.0.0/8':
        table       => 'nat',
        chain       => 'POSTROUTING',
        outiface    => 'eth0',
        destination => '10.0.0.0/8',
        action      => 'accept',
      }
      firewall { '093 ignore 172.16.0.0/12':
        table       => 'nat',
        chain       => 'POSTROUTING',
        outiface    => 'eth0',
        destination => '172.16.0.0/12',
        action      => 'accept',
      }
      firewall { '093 ignore 192.168.0.0/16':
        table       => 'nat',
        chain       => 'POSTROUTING',
        outiface    => 'eth0',
        destination => '192.168.0.0/16',
        action      => 'accept',
      }
      firewall { '100 masq outbound':
        table    => 'nat',
        chain    => 'POSTROUTING',
        outiface => 'eth0',
        jump     => 'MASQUERADE',
      }
      firewall { '101 redirect port 1':
        table   => 'nat',
        chain   => 'PREROUTING',
        iniface => 'eth0',
        proto   => 'tcp',
        dport   => '1',
        toports => '22',
        jump    => 'REDIRECT',
      }
    EOS

    # Run it twice and test for idempotency
    apply_manifest(pp, :catch_failures => true)
    expect(apply_manifest(pp, :catch_failures => true).exit_code).to be_zero
  end

  it 'contains appropriate rules' do
  end
end

describe 'complex ruleset 2' do
  it 'applies cleanly' do
    pp = <<-EOS
      class { '::firewall': }
      
      Firewall {
        proto => 'all',
        stage => 'pre',
      }
      Firewallchain {
        stage  => 'pre',
        purge  => 'true',
        ignore => [
          '--comment "[^"]*(?i:ignore)[^"]*"',
        ],
      }

      firewall { '010 INPUT allow established and related':
        proto  => 'all',
        state  => ['ESTABLISHED', 'RELATED'],
        action => 'accept',
        before => Firewallchain['INPUT:filter:IPv4'],
      }
      firewall { '012 accept loopback':
        iniface => 'lo',
        action  => 'accept',
        before => Firewallchain['INPUT:filter:IPv4'],
      }
      firewall { '020 ssh':
        proto  => 'tcp',
        dport  => '22',
        state  => 'NEW',
        action => 'accept',
        before => Firewallchain['INPUT:filter:IPv4'],
      }

      firewall { '013 icmp echo-request':
        proto  => 'icmp',
        icmp   => 'echo-request',
        action => 'accept',
        source => '10.0.0.0/8',
      }
      firewall { '013 icmp destination-unreachable':
        proto  => 'icmp',
        icmp   => 'destination-unreachable',
        action => 'accept',
      }
      firewall { '013 icmp time-exceeded':
        proto  => 'icmp',
        icmp   => 'time-exceeded',
        action => 'accept',
      }
      firewall { '999 reject':
        action => 'reject',
        reject => 'icmp-host-prohibited',
      }


      firewallchain { 'LOCAL_INPUT_PRE:filter:IPv4': }
      firewall { '001 LOCAL_INPUT_PRE':
        jump    => 'LOCAL_INPUT_PRE',
        require => Firewallchain['LOCAL_INPUT_PRE:filter:IPv4'],
      }
      firewallchain { 'LOCAL_INPUT:filter:IPv4': }
      firewall { '900 LOCAL_INPUT':
        jump    => 'LOCAL_INPUT',
        require => Firewallchain['LOCAL_INPUT:filter:IPv4'],
      }
      firewallchain { 'INPUT:filter:IPv4':
        policy => 'drop',
        ignore => [
          '-j fail2ban-ssh',
          '--comment "[^"]*(?i:ignore)[^"]*"',
        ],
      }


      firewall { '010 allow established and related':
        chain  => 'FORWARD',
        proto  => 'all',
        state  => ['ESTABLISHED','RELATED'],
        action => 'accept',
        before => Firewallchain['FORWARD:filter:IPv4'],
      }
      firewallchain { 'FORWARD:filter:IPv4':
        policy => 'drop',
      }

      firewallchain { 'OUTPUT:filter:IPv4': }


      # purge unknown rules from mangle table
      firewallchain { ['PREROUTING:mangle:IPv4', 'INPUT:mangle:IPv4', 'FORWARD:mangle:IPv4', 'OUTPUT:mangle:IPv4', 'POSTROUTING:mangle:IPv4']: }

      # and the nat table
      firewallchain { ['PREROUTING:nat:IPv4', 'INPUT:nat:IPv4', 'OUTPUT:nat:IPv4', 'POSTROUTING:nat:IPv4']: }
    EOS

    # Run it twice and test for idempotency
    apply_manifest(pp, :catch_failures => true)
    expect(apply_manifest(pp, :catch_failures => true).exit_code).to be_zero
  end

  it 'contains appropriate rules' do
  end
end

