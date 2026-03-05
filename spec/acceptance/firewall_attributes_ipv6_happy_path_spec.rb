# frozen_string_literal: true

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
        firewall { '571 - hop_limit':
          ensure    => present,
          proto     => tcp,
          dport     => '571',
          jump      => accept,
          hop_limit => '5',
          protocol  => 'ip6tables',
        }
        firewall { '576 - checksum_fill':
          proto         => udp,
          table         => 'mangle',
          outiface      => 'virbr0',
          chain         => 'POSTROUTING',
          dport         => '68',
          jump          => 'CHECKSUM',
          checksum_fill => true,
          protocol      => ip6tables,
        }
        firewall { '587 - ishasmorefrags true':
          ensure         => present,
          proto          => tcp,
          dport          => '587',
          jump           => accept,
          ishasmorefrags => true,
          protocol       => 'ip6tables',
        }
        firewall { '588 - ishasmorefrags false':
          ensure         => present,
          proto          => tcp,
          dport          => '588',
          jump           => accept,
          ishasmorefrags => false,
          protocol       => 'ip6tables',
        }
        firewall { '589 - islastfrag true':
          ensure     => present,
          proto      => tcp,
          dport      => '589',
          jump       => accept,
          islastfrag => true,
          protocol   => 'ip6tables',
        }
        firewall { '590 - islastfrag false':
          ensure     => present,
          proto      => tcp,
          dport      => '590',
          jump       => accept,
          islastfrag => false,
          protocol   => 'ip6tables',
        }
        firewall { '591 - isfirstfrag true':
          ensure      => present,
          proto       => tcp,
          dport       => '591',
          jump        => accept,
          isfirstfrag => true,
          protocol    => 'ip6tables',
        }
        firewall { '592 - isfirstfrag false':
          ensure      => present,
          proto       => tcp,
          dport       => '592',
          jump        => accept,
          isfirstfrag => false,
          protocol    => 'ip6tables',
        }
        firewall { '593 - tcpfrags':
          proto     => tcp,
          jump      => accept,
          tcp_flags => 'FIN,SYN ACK',
          protocol  => 'ip6tables',
        }
        firewall { '601 - src_range':
          proto     => tcp,
          dport     => '601',
          jump      => accept,
          src_range => '2001:db8::1-2001:db8::ff',
          protocol  => 'ip6tables',
        }
        firewall { '602 - dst_range':
          proto     => tcp,
          dport     => '602',
          jump      => accept,
          dst_range => '2001:db8::1-2001:db8::ff',
          protocol  => 'ip6tables',
        }
        firewall { '604 - mac_source':
          ensure      => present,
          source      => '2001:db8::1/128',
          mac_source  => '0A:1B:3C:4D:5E:6F',
          chain       => 'INPUT',
          protocol    => 'ip6tables',
        }
        firewall { '605 - socket true':
          ensure   => present,
          proto    => tcp,
          dport    => '605',
          jump     => accept,
          chain    => 'INPUT',
          socket   => true,
          protocol => 'ip6tables',
        }
        firewall { '606 - socket false':
          ensure   => present,
          proto    => tcp,
          dport    => '606',
          jump     => accept,
          chain    => 'INPUT',
          socket   => false,
          protocol => 'ip6tables',
        }
        firewall { '607 - ipsec_policy ipsec':
          ensure       => 'present',
          jump         => 'reject',
          chain        => 'OUTPUT',
          destination  => '2001:db8::1/128',
          ipsec_dir    => 'out',
          ipsec_policy => 'ipsec',
          proto        => 'all',
          reject       => 'icmp6-adm-prohibited',
          table        => 'filter',
          protocol     => 'ip6tables',
        }
        firewall { '608 - ipsec_policy none':
          ensure       => 'present',
          jump         => 'reject',
          chain        => 'OUTPUT',
          destination  => '2001:db8::1/128',
          ipsec_dir    => 'out',
          ipsec_policy => 'none',
          proto        => 'all',
          reject       => 'icmp6-adm-prohibited',
          table        => 'filter',
          protocol     => 'ip6tables',
        }
        firewall { '609 - ipsec_dir out':
          ensure       => 'present',
          jump         => 'reject',
          chain        => 'OUTPUT',
          destination  => '2001:db8::1/128',
          ipsec_dir    => 'out',
          ipsec_policy => 'ipsec',
          proto        => 'all',
          reject       => 'icmp6-adm-prohibited',
          table        => 'filter',
          protocol     => 'ip6tables',
        }
        firewall { '610 - ipsec_dir in':
          ensure       => 'present',
          jump         => 'reject',
          chain        => 'INPUT',
          destination  => '2001:db8::1/128',
          ipsec_dir    => 'in',
          ipsec_policy => 'none',
          proto        => 'all',
          reject       => 'icmp6-adm-prohibited',
          table        => 'filter',
          protocol     => 'ip6tables',
        }
        firewall { '611 - set_mark':
          ensure   => present,
          chain    => 'OUTPUT',
          proto    => tcp,
          dport    => '611',
          jump     => 'MARK',
          table    => 'mangle',
          set_mark => '0x3e8/0xffffffff',
          protocol => 'ip6tables',
        }
        firewall { '613 - dst_type MULTICAST':
          proto    => tcp,
          jump     => accept,
          dst_type => 'MULTICAST',
          protocol => 'ip6tables',
        }
        firewall { '614 - src_type MULTICAST':
          proto    => tcp,
          jump     => accept,
          src_type => 'MULTICAST',
          protocol => 'ip6tables',
        }
        firewall { '615 - dst_type ! MULTICAST':
          proto    => tcp,
          jump     => accept,
          dst_type => '! MULTICAST',
          protocol => 'ip6tables',
        }
        firewall { '616 - src_type ! MULTICAST':
          proto    => tcp,
          jump     => accept,
          src_type => '! MULTICAST',
          protocol => 'ip6tables',
        }
        firewall { '619 - dst_type multiple values':
          proto    => tcp,
          jump     => accept,
          dst_type => ['LOCAL', '! LOCAL'],
          protocol => 'ip6tables',
        }
        firewall { '620 - src_type multiple values':
          proto    => tcp,
          jump     => accept,
          src_type => ['LOCAL', '! LOCAL'],
          protocol => 'ip6tables',
        }
        firewall { '621 - reject with tcp-reset':
          proto    => tcp,
          jump     => reject,
          reject   => 'tcp-reset',
          protocol => 'ip6tables',
        }
        firewall { '801 - ipt_modules tests':
          proto              => tcp,
          dport              => '8080',
          jump               => reject,
          chain              => 'OUTPUT',
          protocol           => 'ip6tables',
          uid                => 0,
          gid                => 404,
          src_range          => "2001::-2002::",
          dst_range          => "2003::-2004::",
          src_type           => 'LOCAL',
          dst_type           => 'UNICAST',
          physdev_in         => "eth0",
          physdev_out        => "eth1",
          physdev_is_bridged => true,
        }
        firewall { '802 - ipt_modules tests':
          proto              => tcp,
          dport              => '8080',
          jump               => reject,
          chain              => 'OUTPUT',
          protocol           => 'ip6tables',
          gid                => 404,
          dst_range          => "2003::-2004::",
          dst_type           => 'UNICAST',
          physdev_out        => "eth1",
          physdev_is_bridged => true,
        }
        firewall { '806 - hashlimit_above test ipv6':
          chain                       => 'INPUT',
          protocol                    => 'ip6tables',
          proto                       => 'tcp',
          hashlimit_name              => 'above-ip6',
          hashlimit_above             => '526/sec',
          hashlimit_htable_gcinterval => 10,
          hashlimit_mode              => 'srcip,dstip',
          jump                        => accept,
        }
        firewall { '811 - tee_gateway6':
          chain    => 'PREROUTING',
          table    => 'mangle',
          jump     => 'TEE',
          gateway  => '2001:db8::1',
          proto    => all,
          protocol => 'ip6tables',
        }
        firewall { '812 - hex_string':
          chain       => 'INPUT',
          proto       => 'tcp',
          string_hex  => '|f4 6d 04 25 b2 02 00 0a|',
          string_algo => 'kmp',
          string_to   => 65534,
          jump        => accept,
          protocol    => 'ip6tables',
        }
        firewall { '500 allow v6 non-any queries':
          chain       => 'OUTPUT',
          proto       => 'udp',
          dport       => '53',
          string_hex  => '! |0000ff0001|',
          string_algo => 'bm',
          string_to   => 65534,
          jump        => 'accept',
          protocol    => 'ip6tables',
        }
      PUPPETCODE
      idempotent_apply(pp)
    end

    let(:result) { run_shell('ip6tables-save') }

    it 'hop_limit is set' do
      expect(result.stdout).to match(%r{-A INPUT -p (tcp|6) -m tcp --dport 571 -m hl --hl-eq 5 -m comment --comment "571 - hop_limit" -j ACCEPT})
    end

    it 'checksum_fill is set' do
      expect(result.stdout).to match(%r{-A POSTROUTING -o virbr0 -p (udp|17) -m udp --dport 68 -m comment --comment "576 - checksum_fill" -j CHECKSUM --checksum-fill})
    end

    it 'ishasmorefrags when true' do
      expect(result.stdout).to match(%r{A INPUT -p (tcp|6) -m frag --fragid 0 --fragmore -m tcp --dport 587 -m comment --comment "587 - ishasmorefrags true" -j ACCEPT})
    end

    it 'ishasmorefrags when false' do
      expect(result.stdout).to match(%r{-A INPUT -p (tcp|6) -m tcp --dport 588 -m comment --comment "588 - ishasmorefrags false" -j ACCEPT})
    end

    it 'islastfrag when true' do
      expect(result.stdout).to match(%r{-A INPUT -p (tcp|6) -m frag --fragid 0 --fraglast -m tcp --dport 589 -m comment --comment "589 - islastfrag true" -j ACCEPT})
    end

    it 'islastfrag when false' do
      expect(result.stdout).to match(%r{-A INPUT -p (tcp|6) -m tcp --dport 590 -m comment --comment "590 - islastfrag false" -j ACCEPT})
    end

    it 'isfirstfrag when true' do
      expect(result.stdout).to match(%r{-A INPUT -p (tcp|6) -m frag --fragid 0 --fragfirst -m tcp --dport 591 -m comment --comment "591 - isfirstfrag true" -j ACCEPT})
    end

    it 'isfirstfrag when false' do
      expect(result.stdout).to match(%r{-A INPUT -p (tcp|6) -m tcp --dport 592 -m comment --comment "592 - isfirstfrag false" -j ACCEPT})
    end

    it 'tcp_flags is set' do
      expect(result.stdout).to match(%r{-A INPUT -p (tcp|6) -m tcp --tcp-flags FIN,SYN ACK -m comment --comment "593 - tcpfrags" -j ACCEPT})
    end

    it 'src_range is set' do
      expect(result.stdout).to match(%r{-A INPUT -p (tcp|6) -m iprange --src-range 2001:db8::1-2001:db8::ff -m tcp --dport 601 -m comment --comment "601 - src_range" -j ACCEPT})
    end

    it 'dst_range is set' do
      expect(result.stdout).to match(%r{-A INPUT -p (tcp|6) -m iprange --dst-range 2001:db8::1-2001:db8::ff -m tcp --dport 602 -m comment --comment "602 - dst_range" -j ACCEPT})
    end

    it 'mac_source is set' do
      expect(result.stdout).to match(%r{-A INPUT -s 2001:db8::1/(128|ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff) -p (tcp|6) -m mac --mac-source 0(a|A):1(b|B):3(c|C):4(d|D):5(e|E):6(f|F) -m comment --comment "604 - mac_source"}) # rubocop:disable Layout/LineLength
    end

    it 'socket when true' do
      expect(result.stdout).to match(%r{-A INPUT -p (tcp|6) -m tcp --dport 605 -m socket -m comment --comment "605 - socket true" -j ACCEPT})
    end

    it 'socket when false' do
      expect(result.stdout).to match(%r{-A INPUT -p (tcp|6) -m tcp --dport 606 -m comment --comment "606 - socket false" -j ACCEPT})
    end

    it 'ipsec_policy when ipsec' do
      expect(result.stdout).to match(
        %r{-A OUTPUT -d 2001:db8::1/(128|ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff) -m policy --dir out --pol ipsec -m comment --comment "607 - ipsec_policy ipsec" -j REJECT --reject-with icmp6-adm-prohibited}, # rubocop:disable Layout/LineLength
      )
    end

    it 'ipsec_policy when none' do
      expect(result.stdout).to match(
        %r{-A OUTPUT -d 2001:db8::1/(128|ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff) -m policy --dir out --pol none -m comment --comment "608 - ipsec_policy none" -j REJECT --reject-with icmp6-adm-prohibited}, # rubocop:disable Layout/LineLength
      )
    end

    it 'ipsec_dir when out' do
      expect(result.stdout).to match(
        %r{-A OUTPUT -d 2001:db8::1/(128|ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff) -m policy --dir out --pol ipsec -m comment --comment "609 - ipsec_dir out" -j REJECT --reject-with icmp6-adm-prohibited}, # rubocop:disable Layout/LineLength
      )
    end

    it 'ipsec_dir when in' do
      expect(result.stdout).to match(
        %r{-A INPUT -d 2001:db8::1/(128|ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff) -m policy --dir in --pol none -m comment --comment "610 - ipsec_dir in" -j REJECT --reject-with icmp6-adm-prohibited},
      )
    end

    it 'set_mark is set' do
      expect(result.stdout).to match(%r{-A OUTPUT -p (tcp|6) -m tcp --dport 611 -m comment --comment "611 - set_mark" -j MARK --set-xmark 0x3e8/0xffffffff})
    end

    it 'dst_type when MULTICAST' do
      expect(result.stdout).to match(%r{-A INPUT -p (tcp|6) -m addrtype\s--dst-type\sMULTICAST -m comment --comment "613 - dst_type MULTICAST" -j ACCEPT})
    end

    it 'src_type when MULTICAST' do
      expect(result.stdout).to match(%r{-A INPUT -p (tcp|6) -m addrtype\s--src-type\sMULTICAST -m comment --comment "614 - src_type MULTICAST" -j ACCEPT})
    end

    it 'dst_type when ! MULTICAST' do
      expect(result.stdout).to match(%r{-A INPUT -p (tcp|6) -m addrtype( !\s--dst-type\sMULTICAST|\s--dst-type\s! MULTICAST) -m comment --comment "615 - dst_type ! MULTICAST" -j ACCEPT})
    end

    it 'src_type when ! MULTICAST' do
      expect(result.stdout).to match(%r{-A INPUT -p (tcp|6) -m addrtype( !\s--src-type\sMULTICAST|\s--src-type\s! MULTICAST) -m comment --comment "616 - src_type ! MULTICAST" -j ACCEPT})
    end

    it 'dst_type when multiple values' do
      expect(result.stdout).to match(%r{-A INPUT -p (tcp|6) -m addrtype --dst-type LOCAL -m addrtype ! --dst-type LOCAL -m comment --comment "619 - dst_type multiple values" -j ACCEPT})
    end

    it 'src_type when multiple values' do
      expect(result.stdout).to match(%r{-A INPUT -p (tcp|6) -m addrtype --src-type LOCAL -m addrtype ! --src-type LOCAL -m comment --comment "620 - src_type multiple values" -j ACCEPT})
    end

    it 'tcp-reset is set' do
      expect(result.stdout).to match(%r{-A INPUT -p (tcp|6) -m comment --comment "621 - reject with tcp-reset" -j REJECT --reject-with tcp-reset})
    end

    it 'all the modules with multiple args is set' do
      expect(result.stdout).to match(%r{-A OUTPUT -p (tcp|6) -m physdev\s+--physdev-in eth0 --physdev-out eth1 --physdev-is-bridged -m iprange --src-range 2001::-2002::\s+--dst-range 2003::-2004:: -m owner --uid-owner (0|root) --gid-owner 404 -m tcp --dport 8080 -m addrtype --src-type LOCAL -m addrtype --dst-type UNICAST -m comment --comment "801 - ipt_modules tests" -j REJECT --reject-with icmp6-port-unreachable}) # rubocop:disable Layout/LineLength
    end

    it 'all the modules with single args is set' do
      expect(result.stdout).to match(%r{-A OUTPUT -p (tcp|6) -m physdev\s+--physdev-out eth1 --physdev-is-bridged -m iprange --dst-range 2003::-2004:: -m owner --gid-owner 404 -m tcp --dport 8080 -m addrtype --dst-type UNICAST -m comment --comment "802 - ipt_modules tests" -j REJECT --reject-with icmp6-port-unreachable}) # rubocop:disable Layout/LineLength
    end

    it 'tee_gateway is set' do
      expect(result.stdout).to match(%r{-A PREROUTING -m comment --comment "811 - tee_gateway6" -j TEE --gateway 2001:db8::1})
    end

    it 'hashlimit_above is set' do
      regex_array = [%r{-A INPUT}, %r{-p (tcp|6)}, %r{--hashlimit-above 526/sec}, %r{--hashlimit-mode srcip,dstip},
                     %r{--hashlimit-name above-ip6}, %r{--hashlimit-htable-gcinterval 10}, %r{-j ACCEPT}]
      regex_array.each do |regex|
        expect(result.stdout).to match(regex)
      end
    end

    it 'checks hex_string value' do
      expect(result.stdout).to match(%r{-A INPUT -p (tcp|6) -m string --hex-string "|f46d0425b202000a|" --algo kmp --to 65535 -m comment --comment "812 - hex_string" -j ACCEPT})
    end

    it 'checks hex_string value which include negation operator' do
      regex_string = %r{-A OUTPUT -p (udp|17) -m udp --dport 53 -m string ! --hex-string "|0000ff0001|" --algo bm --to 65535 -m comment --comment "500 allow v6 non-any queries" -j ACCEPT}
      expect(result.stdout).to match(regex_string)
    end
  end
end
