require 'spec_helper_acceptance'

describe 'firewall attribute testing, happy path' do
  before :all do
    iptables_flush_all_tables
    ip6tables_flush_all_tables
  end

  describe 'attributes test' do
    before(:all) do
      pp = <<-PUPPETCODE
          class { '::firewall': }
          firewall { '004 - log_level and log_prefix':
            chain      => 'INPUT',
            proto      => 'all',
            ctstate    => 'INVALID',
            jump       => 'LOG',
            log_level  => '3',
            log_prefix => 'IPTABLES dropped invalid: ',
          }
          firewall { '501 - connlimit':
            proto           => tcp,
            dport           => '2222',
            connlimit_above => '10',
            connlimit_mask  => '24',
            action          => reject,
          }
          firewall { '502 - connmark':
            proto    => 'all',
            connmark => '0x1',
            action   => reject,
          }
          firewall { '550 - destination':
            proto  => tcp,
            port   => '550',
            action => accept,
            destination => '192.168.2.0/24',
          }
          firewall { '551 - destination negated':
            proto  => tcp,
            port   => '551',
            action => accept,
            destination => '! 192.168.2.0/24',
          }
          firewall { '556 - source':
            proto  => tcp,
            port   => '556',
            action => accept,
            source => '192.168.2.0/24',
          }
          firewall { '557 - source negated':
            proto  => tcp,
            port   => '557',
            action => accept,
            source => '! 192.168.2.0/24',
          }
          firewall { '558 - src_range':
            proto  => tcp,
            port   => '558',
            action => accept,
            src_range => '192.168.1.1-192.168.1.10',
          }
          firewall { '559 - dst_range':
            proto  => tcp,
            port   => '559',
            action => accept,
            dst_range => '192.168.1.1-192.168.1.10',
          }
          firewall { '560 - sport range':
            proto  => tcp,
            sport  => '560-561',
            action => accept,
          }
          firewall { '561 - dport range':
            proto  => tcp,
            dport  => '561-562',
            action => accept,
          }
          firewall { '562 - port range':
            proto  => tcp,
            port  => '562-563',
            action => accept,
          }
          firewall { '563 - dst_type':
            proto  => tcp,
            action => accept,
            dst_type => 'MULTICAST',
          }
          firewall { '564 - src_type negated':
            proto  => tcp,
            action => accept,
            src_type => '! MULTICAST',
          }
          firewall { '565 - tcp_flags':
            proto  => tcp,
            action => accept,
            tcp_flags => 'FIN,SYN ACK',
          }
          firewall { '566 - chain':
            proto  => tcp,
            action => accept,
            chain  => 'FORWARD',
          }
          firewallchain { 'TEST:filter:IPv4':
          ensure => present,
          }
          firewall { '567 - jump':
            proto  => tcp,
            chain  => 'INPUT',
            jump  => 'TEST',
          }
          firewall { '568 - tosource':
            proto  => tcp,
            table  => 'nat',
            chain  => 'POSTROUTING',
            jump  => 'SNAT',
            tosource => '192.168.1.1',
          }
          firewall { '569 - todest':
            proto  => tcp,
            table  => 'nat',
            chain  => 'PREROUTING',
            jump   => 'DNAT',
            source => '200.200.200.200',
            todest => '192.168.1.1',
          }
          firewall { '572 - limit':
            ensure => present,
            proto => tcp,
            port   => '572',
            action => accept,
            limit => '500/sec',
          }
          firewall { '573 - burst':
            ensure => present,
            proto => tcp,
            port   => '573',
            action => accept,
            limit => '500/sec',
            burst => '1500',
          }
          firewall { '574 - toports':
            proto  => icmp,
            table  => 'nat',
            chain  => 'PREROUTING',
            jump  => 'REDIRECT',
            toports => '2222',
          }
          firewall { '581 - pkttype':
            ensure => present,
            proto => tcp,
            port   => '581',
            action => accept,
            pkttype => 'multicast',
          }
          firewall { '583 - isfragment':
            ensure => present,
            proto => tcp,
            port   => '583',
            action => accept,
            isfragment => true,
          }
          firewall { '595 - ipsec_policy ipsec and out':
            ensure       => 'present',
            action       => 'reject',
            chain        => 'OUTPUT',
            destination  => '20.0.0.0/8',
            ipsec_dir    => 'out',
            ipsec_policy => 'ipsec',
            proto        => 'all',
            reject       => 'icmp-net-unreachable',
            table        => 'filter',
          }
          firewall { '596 - ipsec_policy none and in':
            ensure       => 'present',
            action       => 'reject',
            chain        => 'INPUT',
            destination  => '20.0.0.0/8',
            ipsec_dir    => 'in',
            ipsec_policy => 'none',
            proto        => 'all',
            reject       => 'icmp-net-unreachable',
            table        => 'filter',
          }
          firewall { '597 - recent set':
            ensure       => 'present',
            chain        => 'INPUT',
            destination  => '30.0.0.0/8',
            proto        => 'all',
            table        => 'filter',
            recent       => 'set',
            rdest        => true,
            rname        => 'list1',
          }
          firewall { '598 - recent rcheck':
            ensure       => 'present',
            chain        => 'INPUT',
            destination  => '30.0.0.0/8',
            proto        => 'all',
            table        => 'filter',
            recent       => 'rcheck',
            rsource      => true,
            rname        => 'list1',
            rseconds     => 60,
            rhitcount    => 5,
            rttl         => true,
          }
          firewall { '599 - recent update':
            ensure       => 'present',
            chain        => 'INPUT',
            destination  => '30.0.0.0/8',
            proto        => 'all',
            table        => 'filter',
            recent       => 'update',
          }
          firewall { '600 - recent remove':
            ensure       => 'present',
            chain        => 'INPUT',
            destination  => '30.0.0.0/8',
            proto        => 'all',
            table        => 'filter',
            recent       => 'remove',
          }
          firewall { '601 - clamp_mss_to_pmtu':
            proto             => 'tcp',
            chain             => 'FORWARD',
            tcp_flags         => 'SYN,RST SYN',
            jump              => 'TCPMSS',
            clamp_mss_to_pmtu => true,
          }
          firewall { '602 - drop NEW external website packets with FIN/RST/ACK set and SYN unset':
            chain     => 'INPUT',
            ctstate   => 'NEW',
            action    => 'drop',
            proto     => 'tcp',
            sport     => ['! http', '! 443'],
            source    => '! 10.0.0.0/8',
            tcp_flags => '! FIN,SYN,RST,ACK SYN',
          }
          firewall { '603 - disallow esp protocol':
            action => 'accept',
            proto  => '! esp',
          }
          firewall { '604 - set_mss':
            proto     => 'tcp',
            tcp_flags => 'SYN,RST SYN',
            jump      => 'TCPMSS',
            set_mss   => '1360',
            mss       => '1361:1541',
            chain     => 'FORWARD',
            table     => 'mangle',
          }
          firewall { '700 - blah-A Test Rule':
            jump       => 'LOG',
            log_prefix => 'FW-A-INPUT: ',
          }
          firewall { '701 - log_uid':
            chain   => 'OUTPUT',
            jump    => 'LOG',
            log_uid => true,
          }
          firewall { '711 - physdev_in':
            chain => 'FORWARD',
            proto  => tcp,
            port   => '711',
            action => accept,
            physdev_in => 'eth0',
          }
          firewall { '712 - physdev_out':
            chain => 'FORWARD',
            proto  => tcp,
            port   => '712',
            action => accept,
            physdev_out => 'eth1',
          }
          firewall { '713 - physdev_in physdev_out physdev_is_bridged':
            chain => 'FORWARD',
            proto  => tcp,
            port   => '713',
            action => accept,
            physdev_in => 'eth0',
            physdev_out => 'eth1',
            physdev_is_bridged => true,
          }
          firewall { '801 - gid root':
            chain => 'OUTPUT',
            action => accept,
            gid => 'root',
            proto => 'all',
          }
          firewall { '802 - gid root negated':
            chain => 'OUTPUT',
            action => accept,
            gid => '!root',
            proto => 'all',
          }
          firewall { '803 - uid 0':
            chain => 'OUTPUT',
            action => accept,
            uid => '0',
            proto => 'all',
          }
          firewall { '804 - uid 0 negated':
            chain => 'OUTPUT',
            action => accept,
            uid => '!0',
            proto => 'all',
          }

          firewall { '807 - ipt_modules tests':
            proto              => tcp,
            dport              => '8080',
            action             => reject,
            chain              => 'OUTPUT',
            uid                => 0,
            gid                => 404,
            src_range          => "90.0.0.1-90.0.0.2",
            dst_range          => "100.0.0.1-100.0.0.2",
            src_type           => 'LOCAL',
            dst_type           => 'UNICAST',
            physdev_in         => "eth0",
            physdev_out        => "eth1",
            physdev_is_bridged => true,
          }
          firewall { '808 - ipt_modules tests':
            proto              => tcp,
            dport              => '8080',
            action             => reject,
            chain              => 'OUTPUT',
            gid                => 404,
            dst_range          => "100.0.0.1-100.0.0.2",
            dst_type           => 'UNICAST',
            physdev_out        => "eth1",
            physdev_is_bridged => true,
          }
          firewall { '1000 - set_dscp':
            proto     => 'tcp',
            jump      => 'DSCP',
            set_dscp  => '0x01',
            port      => '997',
            chain     => 'OUTPUT',
            table     => 'mangle',
          }
          firewall { '1001 EF - set_dscp_class':
            proto          => 'tcp',
            jump           => 'DSCP',
            port           => '997',
            set_dscp_class => 'EF',
            chain          => 'OUTPUT',
            table          => 'mangle',
          }
      PUPPETCODE
      apply_manifest(pp, catch_failures: true)
      apply_manifest(pp, catch_changes: do_catch_changes)
    end

    let(:result) { shell('iptables-save') }

    it 'log_level and log_prefix' do
      expect(result.stdout).to match(%r{A INPUT -m conntrack --ctstate INVALID -m comment --comment "004 - log_level and log_prefix" -j LOG --log-prefix "IPTABLES dropped invalid: " --log-level 3})
    end
    it 'contains the connlimit and connlimit_mask rule' do
      expect(result.stdout).to match(
        %r{-A INPUT -p tcp -m multiport --dports 2222 -m connlimit --connlimit-above 10 --connlimit-mask 24 (--connlimit-saddr )?-m comment --comment "501 - connlimit" -j REJECT --reject-with icmp-port-unreachable}, # rubocop:disable Metrics/LineLength
      )
    end
    it 'contains connmark' do
      expect(result.stdout).to match(%r{-A INPUT -m connmark --mark 0x1 -m comment --comment "502 - connmark" -j REJECT --reject-with icmp-port-unreachable})
    end
    it 'destination is set' do
      expect(result.stdout).to match(%r{-A INPUT -d 192.168.2.0\/(24|255\.255\.255\.0) -p tcp -m multiport --ports 550 -m comment --comment "550 - destination" -j ACCEPT})
    end
    it 'destination is negated' do
      expect(result.stdout).to match(%r{-A INPUT (! -d|-d !) 192.168.2.0\/(24|255\.255\.255\.0) -p tcp -m multiport --ports 551 -m comment --comment "551 - destination negated" -j ACCEPT})
    end
    it 'source is set' do
      expect(result.stdout).to match(%r{-A INPUT -s 192.168.2.0\/(24|255\.255\.255\.0) -p tcp -m multiport --ports 556 -m comment --comment "556 - source" -j ACCEPT})
    end
    it 'source is negated' do
      expect(result.stdout).to match(%r{-A INPUT (! -s|-s !) 192.168.2.0\/(24|255\.255\.255\.0) -p tcp -m multiport --ports 557 -m comment --comment "557 - source negated" -j ACCEPT})
    end
    it 'src_range is set' do
      expect(result.stdout).to match(%r{-A INPUT -p tcp -m iprange --src-range 192.168.1.1-192.168.1.10 -m multiport --ports 558 -m comment --comment "558 - src_range" -j ACCEPT})
    end
    it 'dst_range is set' do
      expect(result.stdout).to match(%r{-A INPUT -p tcp -m iprange --dst-range 192.168.1.1-192.168.1.10 -m multiport --ports 559 -m comment --comment "559 - dst_range" -j ACCEPT})
    end
    it 'sport range is set' do
      expect(result.stdout).to match(%r{-A INPUT -p tcp -m multiport --sports 560:561 -m comment --comment "560 - sport range" -j ACCEPT})
    end
    it 'dport range is set' do
      expect(result.stdout).to match(%r{-A INPUT -p tcp -m multiport --dports 561:562 -m comment --comment "561 - dport range" -j ACCEPT})
    end
    it 'port range is set' do
      expect(result.stdout).to match(%r{-A INPUT -p tcp -m multiport --ports 562:563 -m comment --comment "562 - port range" -j ACCEPT})
    end
    it 'dst_type is set' do
      expect(result.stdout).to match(%r{-A INPUT -p tcp -m addrtype --dst-type MULTICAST -m comment --comment "563 - dst_type" -j ACCEPT})
    end
    it 'src_type is negated' do
      expect(result.stdout).to match(%r{-A INPUT -p tcp -m addrtype (! --src-type|--src-type !) MULTICAST -m comment --comment "564 - src_type negated" -j ACCEPT})
    end
    it 'tcp_flags is set' do
      expect(result.stdout).to match(%r{-A INPUT -p tcp -m tcp --tcp-flags FIN,SYN ACK -m comment --comment "565 - tcp_flags" -j ACCEPT})
    end
    it 'chain is set' do
      expect(result.stdout).to match(%r{-A FORWARD -p tcp -m comment --comment "566 - chain" -j ACCEPT})
    end
    it 'tosource is set' do
      expect(result.stdout).to match(%r{A POSTROUTING -p tcp -m comment --comment "568 - tosource" -j SNAT --to-source 192.168.1.1})
    end
    it 'todest is set' do
      expect(result.stdout).to match(%r{-A PREROUTING -s 200.200.200.200(\/32)? -p tcp -m comment --comment "569 - todest" -j DNAT --to-destination 192.168.1.1})
    end
    it 'toports is set' do
      expect(result.stdout).to match(%r{-A PREROUTING -p icmp -m comment --comment "574 - toports" -j REDIRECT --to-ports 2222})
    end
    it 'limit is set' do
      expect(result.stdout).to match(%r{-A INPUT -p tcp -m multiport --ports 572 -m limit --limit 500\/sec -m comment --comment "572 - limit" -j ACCEPT})
    end
    it 'burst is set' do
      expect(result.stdout).to match(%r{-A INPUT -p tcp -m multiport --ports 573 -m limit --limit 500\/sec --limit-burst 1500 -m comment --comment "573 - burst" -j ACCEPT})
    end
    it 'pkttype is set' do
      expect(result.stdout).to match(%r{-A INPUT -p tcp -m multiport --ports 581 -m pkttype --pkt-type multicast -m comment --comment "581 - pkttype" -j ACCEPT})
    end
    it 'isfragment is set' do
      expect(result.stdout).to match(%r{-A INPUT -p tcp -f -m multiport --ports 583 -m comment --comment "583 - isfragment" -j ACCEPT})
    end
    it 'ipsec_policy ipsec and dir out' do
      expect(result.stdout).to match(%r{-A OUTPUT -d 20.0.0.0\/(8|255\.0\.0\.0) -m policy --dir out --pol ipsec -m comment --comment "595 - ipsec_policy ipsec and out" -j REJECT --reject-with icmp-net-unreachable}) # rubocop:disable Metrics/LineLength
    end
    it 'ipsec_policy none and dir in' do
      expect(result.stdout).to match(%r{-A INPUT -d 20.0.0.0\/(8|255\.0\.0\.0) -m policy --dir in --pol none -m comment --comment "596 - ipsec_policy none and in" -j REJECT --reject-with icmp-net-unreachable}) # rubocop:disable Metrics/LineLength
    end
    it 'set_mss is set' do
      expect(result.stdout).to match(%r{-A FORWARD -p tcp -m tcp --tcp-flags SYN,RST SYN -m tcpmss --mss 1361:1541 -m comment --comment "604 - set_mss" -j TCPMSS --set-mss 1360})
    end
    it 'clamp_mss_to_pmtu is set' do
      expect(result.stdout).to match(%r{-A FORWARD -p tcp -m tcp --tcp-flags SYN,RST SYN -m comment --comment "601 - clamp_mss_to_pmtu" -j TCPMSS --clamp-mss-to-pmtu})
    end
    it 'comment containing "-A "' do
      expect(result.stdout).to match(%r{-A INPUT -p tcp -m comment --comment "700 - blah-A Test Rule" -j LOG --log-prefix "FW-A-INPUT: "})
    end
    it 'set log_uid' do
      expect(result.stdout).to match(%r{-A OUTPUT -p tcp -m comment --comment "701 - log_uid" -j LOG --log-uid})
    end
    it 'set physdev_in' do
      expect(result.stdout).to match(%r{-A FORWARD -p tcp -m physdev\s+--physdev-in eth0 -m multiport --ports 711 -m comment --comment "711 - physdev_in" -j ACCEPT})
    end
    it 'set physdev_out' do
      expect(result.stdout).to match(%r{-A FORWARD -p tcp -m physdev\s+--physdev-out eth1 -m multiport --ports 712 -m comment --comment "712 - physdev_out" -j ACCEPT})
    end
    it 'physdev_in eth0 and physdev_out eth1 and physdev_is_bridged' do
      expect(result.stdout).to match(%r{-A FORWARD -p tcp -m physdev\s+--physdev-in eth0 --physdev-out eth1 --physdev-is-bridged -m multiport --ports 713 -m comment --comment "713 - physdev_in physdev_out physdev_is_bridged" -j ACCEPT}) # rubocop:disable Metrics/LineLength
    end
    it 'gid set to root' do
      expect(result.stdout).to match(%r{-A OUTPUT -m owner --gid-owner (0|root) -m comment --comment "801 - gid root" -j ACCEPT})
    end
    it 'gid set to root negated' do
      expect(result.stdout).to match(%r{-A OUTPUT -m owner ! --gid-owner (0|root) -m comment --comment "802 - gid root negated" -j ACCEPT})
    end
    it 'uid set to 0' do
      expect(result.stdout).to match(%r{-A OUTPUT -m owner --uid-owner (0|root) -m comment --comment "803 - uid 0" -j ACCEPT})
    end
    it 'uid set to 0 negated' do
      expect(result.stdout).to match(%r{-A OUTPUT -m owner ! --uid-owner (0|root) -m comment --comment "804 - uid 0 negated" -j ACCEPT})
    end
    it 'set_dscp is set' do
      expect(result.stdout).to match(%r{-A OUTPUT -p tcp -m multiport --ports 997 -m comment --comment "1000 - set_dscp" -j DSCP --set-dscp 0x01})
    end
    it 'set_dscp_class is set' do
      expect(result.stdout).to match(%r{-A OUTPUT -p tcp -m multiport --ports 997 -m comment --comment "1001 EF - set_dscp_class" -j DSCP --set-dscp 0x2e})
    end
    it 'all the modules with multiple args is set' do
      expect(result.stdout).to match(%r{-A OUTPUT -p tcp -m physdev\s+--physdev-in eth0 --physdev-out eth1 --physdev-is-bridged -m iprange --src-range 90.0.0.1-90.0.0.2\s+--dst-range 100.0.0.1-100.0.0.2 -m owner --uid-owner (0|root) --gid-owner 404 -m multiport --dports 8080 -m addrtype --src-type LOCAL --dst-type UNICAST -m comment --comment "807 - ipt_modules tests" -j REJECT --reject-with icmp-port-unreachable}) # rubocop:disable Metrics/LineLength
    end
    it 'all the modules with single args is set' do
      expect(result.stdout).to match(%r{-A OUTPUT -p tcp -m physdev\s+--physdev-out eth1 --physdev-is-bridged -m iprange --dst-range 100.0.0.1-100.0.0.2 -m owner --gid-owner 404 -m multiport --dports 8080 -m addrtype --dst-type UNICAST -m comment --comment "808 - ipt_modules tests" -j REJECT --reject-with icmp-port-unreachable}) # rubocop:disable Metrics/LineLength
    end
    it 'inverting rules' do
      regex_array = [%r{-A INPUT (-s !|! -s) (10\.0\.0\.0\/8|10\.0\.0\.0\/255\.0\.0\.0).*}, %r{-A INPUT.*(--sports !|! --sports) 80,443.*},
                     %r{-A INPUT.*-m tcp ! --tcp-flags FIN,SYN,RST,ACK SYN.*}, %r{-A INPUT.*-j DROP},
                     %r{-A INPUT (! -p|-p !) esp -m comment --comment "603 - disallow esp protocol" -j ACCEPT}]

      regex_array.each do |regex|
        expect(result.stdout).to match(regex)
      end
    end
    it 'recent set to set' do
      expect(result.stdout).to match(%r{-A INPUT -d 30.0.0.0\/(8|255\.0\.0\.0) -m recent --set --name list1 (--mask 255.255.255.255 )?--rdest -m comment --comment "597 - recent set"})
    end
    it 'recent set to rcheck' do
      expect(result.stdout).to match(%r{-A INPUT -d 30.0.0.0\/(8|255\.0\.0\.0) -m recent --rcheck --seconds 60 --hitcount 5 --rttl --name list1 (--mask 255.255.255.255 )?--rsource -m comment --comment "598 - recent rcheck"}) # rubocop:disable Metrics/LineLength
    end
    it 'recent set to update' do
      expect(result.stdout).to match(%r{-A INPUT -d 30.0.0.0\/(8|255\.0\.0\.0) -m recent --update --name DEFAULT (--mask 255.255.255.255 )?--rsource -m comment --comment "599 - recent update"})
    end
    it 'recent set to remove' do
      expect(result.stdout).to match(%r{-A INPUT -d 30.0.0.0\/(8|255\.0\.0\.0) -m recent --remove --name DEFAULT (--mask 255.255.255.255 )?--rsource -m comment --comment "600 - recent remove"})
    end
    it 'jump is set' do
      expect(result.stdout).to match(%r{-A INPUT -p tcp -m comment --comment "567 - jump" -j TEST})
    end
  end
end
