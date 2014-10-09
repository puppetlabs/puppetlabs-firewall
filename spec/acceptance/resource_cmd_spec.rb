require 'spec_helper_acceptance'

# Here we want to test the the resource commands ability to work with different
# existing ruleset scenarios. This will give the parsing capabilities of the
# code a good work out.
describe 'puppet resource firewall command:', :unless => UNSUPPORTED_PLATFORMS.include?(fact('osfamily')) do
  context 'make sure it returns no errors when executed on a clean machine' do
    it do
      shell('puppet resource firewall') do |r|
        r.exit_code.should be_zero
        # don't check stdout, some boxes come with rules, that is normal
        # don't check stderr, puppet throws deprecation warnings
      end
    end
  end

  context 'flush iptables and make sure it returns nothing afterwards' do
    before(:all) do
      iptables_flush_all_tables
    end

    # No rules, means no output thanks. And no errors as well.
    it do
      shell('puppet resource firewall') do |r|
        r.exit_code.should be_zero
        r.stdout.should == "\n"
      end
    end
  end

  context 'accepts rules without comments' do
    before(:all) do
      iptables_flush_all_tables
      shell('iptables -A INPUT -j ACCEPT -p tcp --dport 80')
    end

    it do
      shell('puppet resource firewall') do |r|
        r.exit_code.should be_zero
        # don't check stdout, testing preexisting rules, output is normal
        # don't check stderr, puppet throws deprecation warnings
      end
    end
  end

  context 'accepts rules with invalid comments' do
    before(:all) do
      iptables_flush_all_tables
      shell('iptables -A INPUT -j ACCEPT -p tcp --dport 80 -m comment --comment "http"')
    end

    it do
      shell('puppet resource firewall') do |r|
        r.exit_code.should be_zero
        # don't check stdout, testing preexisting rules, output is normal
        # don't check stderr, puppet throws deprecation warnings
      end
    end
  end

  context 'accepts rules with negation' do
    before :all do
      iptables_flush_all_tables
      shell('iptables -t nat -A POSTROUTING -s 192.168.122.0/24 ! -d 192.168.122.0/24 -p tcp -j MASQUERADE --to-ports 1024-65535')
      shell('iptables -t nat -A POSTROUTING -s 192.168.122.0/24 ! -d 192.168.122.0/24 -p udp -j MASQUERADE --to-ports 1024-65535')
      shell('iptables -t nat -A POSTROUTING -s 192.168.122.0/24 ! -d 192.168.122.0/24 -j MASQUERADE')
    end

    it do
      shell('puppet resource firewall') do |r|
        r.exit_code.should be_zero
        # don't check stdout, testing preexisting rules, output is normal
        # don't check stderr, puppet throws deprecation warnings
      end
    end
  end

  context 'accepts rules with match extension tcp flag' do
    before :all do
      iptables_flush_all_tables
      shell('iptables -t mangle -A PREROUTING -d 1.2.3.4 -p tcp -m tcp -m multiport --dports 80,443,8140 -j MARK --set-mark 42')
    end

    it do
      shell('puppet resource firewall') do |r|
        r.exit_code.should be_zero
        # don't check stdout, testing preexisting rules, output is normal
        # don't check stderr, puppet throws deprecation warnings
      end
    end
  end

  context 'accepts rules utilizing the statistic module' do
    before :all do
      iptables_flush_all_tables
      # This command doesn't work with all versions/oses, so let it fail
      shell('iptables -t nat -A POSTROUTING -d 1.2.3.4/32 -o eth0 -m statistic --mode nth --every 2 -j SNAT --to-source 2.3.4.5', :acceptable_exit_codes => [0,1,2] )
      shell('iptables -t nat -A POSTROUTING -d 1.2.3.4/32 -o eth0 -m statistic --mode nth --every 1 --packet 0 -j SNAT --to-source 2.3.4.6')
      shell('iptables -t nat -A POSTROUTING -d 1.2.3.4/32 -o eth0 -m statistic --mode random --probability 0.99 -j SNAT --to-source 2.3.4.7')
    end

    it do
      shell('puppet resource firewall') do |r|
        r.exit_code.should be_zero
        # don't check stdout, testing preexisting rules, output is normal
        # don't check stderr, puppet throws deprecation warnings
      end
    end
  end

  context 'accepts rules with negation' do
    before :all do
      iptables_flush_all_tables
      shell('iptables -t nat -A POSTROUTING -s 192.168.122.0/24 -m policy --dir out --pol ipsec -j ACCEPT')
      shell('iptables -t filter -A FORWARD -s 192.168.1.0/24 -d 192.168.122.0/24 -i eth0 -m policy --dir in --pol ipsec --reqid 108 --proto esp -j ACCEPT')
      shell('iptables -t filter -A FORWARD -s 192.168.122.0/24 -d 192.168.1.0/24 -o eth0 -m policy --dir out --pol ipsec --reqid 108 --proto esp -j ACCEPT')
      shell('iptables -t filter -A FORWARD -s 192.168.201.1/32 -d 192.168.122.0/24 -i eth0 -m policy --dir in --pol ipsec --reqid 107 --proto esp -j ACCEPT')
      shell('iptables -t filter -A FORWARD -s 192.168.122.0/24 -d 192.168.201.1/32 -o eth0 -m policy --dir out --pol ipsec --reqid 107 --proto esp -j ACCEPT')
    end

    it do
      shell('puppet resource firewall') do |r|
        r.exit_code.should be_zero
        # don't check stdout, testing preexisting rules, output is normal
        # don't check stderr, puppet throws deprecation warnings
      end
    end
  end
end
