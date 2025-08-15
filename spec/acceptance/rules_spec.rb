# frozen_string_literal: true

require 'spec_helper_acceptance'
require 'spec_helper_acceptance_local'

describe 'rules spec' do
  describe 'complex ruleset 1' do
    before :all do
      pre_setup if os[:family] == 'redhat'
      iptables_flush_all_tables
      ip6tables_flush_all_tables
    end

    after :all do
      run_shell('iptables -t filter -P INPUT ACCEPT')
      run_shell('iptables -t filter -P FORWARD ACCEPT')
      run_shell('iptables -t filter -P OUTPUT ACCEPT')
      run_shell('iptables -t filter --flush')
    end

    pp1 = <<-PUPPETCODE
        firewall { '090 forward allow local':
          chain       => 'FORWARD',
          proto       => 'all',
          source      => '10.0.0.0/8',
          destination => '10.0.0.0/8',
          jump        => 'ACCEPT',
        }
        firewall { '100 forward standard allow tcp':
          chain       => 'FORWARD',
          source      => '10.0.0.0/8',
          destination => '! 10.0.0.0/8',
          proto       => 'tcp',
          ctstate     => 'NEW',
          sport       => ['80','443','21','20','22','53','123','43','873','25','465'],
          jump        => 'ACCEPT',
        }
        firewall { '100 forward standard allow udp':
          chain       => 'FORWARD',
          source      => '10.0.0.0/8',
          destination => '! 10.0.0.0/8',
          proto       => 'udp',
          sport       => ['53','123'],
          jump        => 'ACCEPT',
        }
        firewall { '100 forward standard allow icmp':
          chain       => 'FORWARD',
          source      => '10.0.0.0/8',
          destination => '! 10.0.0.0/8',
          proto       => 'icmp',
          jump        => 'ACCEPT',
        }

        firewall { '090 ignore ipsec':
          table        => 'nat',
          chain        => 'POSTROUTING',
          outiface     => 'eth0',
          ipsec_policy => 'ipsec',
          ipsec_dir    => 'out',
          jump         => 'ACCEPT',
        }
        firewall { '093 ignore 10.0.0.0/8':
          table       => 'nat',
          chain       => 'POSTROUTING',
          outiface    => 'eth0',
          destination => '10.0.0.0/8',
          jump        => 'ACCEPT',
        }
        firewall { '093 ignore 172.16.0.0/12':
          table       => 'nat',
          chain       => 'POSTROUTING',
          outiface    => 'eth0',
          destination => '172.16.0.0/12',
          jump        => 'ACCEPT',
        }
        firewall { '093 ignore 192.168.0.0/16':
          table       => 'nat',
          chain       => 'POSTROUTING',
          outiface    => 'eth0',
          destination => '192.168.0.0/16',
          jump        => 'ACCEPT',
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
          sport   => '1',
          toports => '22',
          jump    => 'REDIRECT',
        }
    PUPPETCODE
    it 'applies cleanly' do
      idempotent_apply(pp1)
    end

    regex_values = [
      %r{INPUT ACCEPT}, %r{FORWARD ACCEPT}, %r{OUTPUT ACCEPT},
      %r{-A FORWARD -s 10.0.0.0/(8|255\.0\.0\.0) -d 10.0.0.0/(8|255\.0\.0\.0) -m comment --comment "090 forward allow local" -j ACCEPT},
      %r{-A FORWARD -s 10.0.0.0/(8|255\.0\.0\.0) (! -d|-d !) 10.0.0.0/(8|255\.0\.0\.0) -p (icmp|1) -m comment --comment "100 forward standard allow icmp" -j ACCEPT},
      %r{-A FORWARD -s 10.0.0.0/(8|255\.0\.0\.0) (! -d|-d !) 10.0.0.0/(8|255\.0\.0\.0) -p (tcp|6) -m multiport --sports 80,443,21,20,22,53,123,43,873,25,465 -m conntrack --ctstate NEW -m comment --comment "100 forward standard allow tcp" -j ACCEPT}, # rubocop:disable Layout/LineLength
      %r{-A FORWARD -s 10.0.0.0/(8|255\.0\.0\.0) (! -d|-d !) 10.0.0.0/(8|255\.0\.0\.0) -p (udp|17) -m multiport --sports 53,123 -m comment --comment "100 forward standard allow udp" -j ACCEPT}
    ]
    it 'contains appropriate rules' do
      run_shell('iptables-save') do |r|
        regex_values.each do |line|
          expect(r.stdout).to match(line)
        end
      end
    end
  end

  describe 'complex ruleset 2' do
    after :all do
      run_shell('iptables -t filter -P INPUT ACCEPT')
      run_shell('iptables -t filter -P FORWARD ACCEPT')
      run_shell('iptables -t filter -P OUTPUT ACCEPT')
      run_shell('iptables -t filter --flush')
    end

    pp2 = <<-PUPPETCODE
        class { 'firewall': }

        Firewall {
          proto => 'all',
        }
        Firewallchain {
          purge  => true,
          ignore => [
            '--comment "[^"]*(?i:ignore)[^"]*"',
          ],
        }

        firewall { '001 ssh needed for beaker testing':
          proto   => 'tcp',
          dport   => '22',
          jump    => 'ACCEPT',
          before => Firewallchain['INPUT:filter:IPv4'],
        }

        firewall { '010 INPUT allow established and related':
          proto  => 'all',
          ctstate  => ['ESTABLISHED', 'RELATED'],
          jump   => 'ACCEPT',
          before => Firewallchain['INPUT:filter:IPv4'],
        }

        firewall { "011 reject local traffic not on loopback interface":
          iniface     => '! lo',
          proto       => 'all',
          destination => '127.0.0.0/8',
          jump        => 'REJECT',
        }
        firewall { '012 accept loopback':
          iniface => 'lo',
          jump    => 'ACCEPT',
          before => Firewallchain['INPUT:filter:IPv4'],
        }
        firewall { '020 ssh':
          proto  => 'tcp',
          dport  => '22',
          ctstate  => 'NEW',
          jump   => 'ACCEPT',
          before => Firewallchain['INPUT:filter:IPv4'],
        }

        firewall { '025 smtp':
          outiface => '! eth0:2',
          chain    => 'OUTPUT',
          proto    => 'tcp',
          dport    => '25',
          ctstate    => 'NEW',
          jump     => 'ACCEPT',
        }
        firewall { '013 icmp echo-request':
          proto  => 'icmp',
          icmp   => 'echo-request',
          jump   => 'ACCEPT',
          source => '10.0.0.0/8',
        }
        firewall { '013 icmp destination-unreachable':
          proto  => 'icmp',
          icmp   => 'destination-unreachable',
          jump   => 'ACCEPT',
        }
        firewall { '013 icmp time-exceeded':
          proto  => 'icmp',
          icmp   => 'time-exceeded',
          jump   => 'ACCEPT',
        }
        firewall { '014 icmp destination-unreachable/fragmentation-needed':
          proto  => 'icmp',
          icmp   => '3/4',
          jump   => 'ACCEPT',
        }

        firewall { '443 ssl on aliased interface':
          proto   => 'tcp',
          dport   => '443',
          ctstate   => 'NEW',
          jump    => 'ACCEPT',
          iniface => 'eth0:3',
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
          ctstate  => ['ESTABLISHED','RELATED'],
          jump   => 'ACCEPT',
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
    PUPPETCODE
    it 'applies cleanly' do
      # Run it twice and test for idempotency
      idempotent_apply(pp2)
    end

    regex_values = [
      %r{INPUT DROP},
      %r{FORWARD DROP},
      %r{OUTPUT ACCEPT},
      %r{LOCAL_INPUT},
      %r{LOCAL_INPUT_PRE},
      %r{-A INPUT -m comment --comment "001 LOCAL_INPUT_PRE" -j LOCAL_INPUT_PRE},
      %r{-A INPUT -p (tcp|6) -m tcp --dport 22 -m comment --comment "001 ssh needed for beaker testing" -j ACCEPT},
      %r{-A INPUT -m conntrack --ctstate RELATED,ESTABLISHED -m comment --comment "010 INPUT allow established and related" -j ACCEPT},
      %r{-A INPUT -d 127.0.0.0/(8|255\.0\.0\.0) (! -i|-i !) lo -m comment --comment "011 reject local traffic not on loopback interface" -j REJECT --reject-with icmp-port-unreachable},
      %r{-A INPUT -i lo -m comment --comment "012 accept loopback" -j ACCEPT},
      %r{-A INPUT -p (icmp|1) -m icmp --icmp-type 3 -m comment --comment "013 icmp destination-unreachable" -j ACCEPT},
      %r{-A INPUT -s 10.0.0.0/(8|255\.0\.0\.0) -p (icmp|1) -m icmp --icmp-type 8 -m comment --comment "013 icmp echo-request" -j ACCEPT},
      %r{-A INPUT -p (icmp|1) -m icmp --icmp-type 11 -m comment --comment "013 icmp time-exceeded" -j ACCEPT},
      %r{-A INPUT -p (icmp|1) -m icmp --icmp-type 3/4 -m comment --comment "014 icmp destination-unreachable/fragmentation-needed" -j ACCEPT},
      %r{-A INPUT -p (tcp|6) -m tcp --dport 22 -m conntrack --ctstate NEW -m comment --comment "020 ssh" -j ACCEPT},
      %r{-A INPUT -i eth0:3 -p (tcp|6) -m tcp --dport 443 -m conntrack --ctstate NEW -m comment --comment "443 ssl on aliased interface" -j ACCEPT},
      %r{-A INPUT -m comment --comment "900 LOCAL_INPUT" -j LOCAL_INPUT},
      %r{-A FORWARD -m conntrack --ctstate RELATED,ESTABLISHED -m comment --comment "010 allow established and related" -j ACCEPT},
      %r{-A OUTPUT (! -o|-o !) eth0:2 -p (tcp|6) -m tcp --dport 25 -m conntrack --ctstate NEW -m comment --comment "025 smtp" -j ACCEPT},
    ]
    it 'contains appropriate rules' do
      run_shell('iptables-save') do |r|
        regex_values.each do |line|
          expect(r.stdout).to match(line)
        end
      end
    end
  end
end
