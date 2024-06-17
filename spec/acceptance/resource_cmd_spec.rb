# frozen_string_literal: true

require 'spec_helper_acceptance'

# Here we want to test the the resource commands ability to work with different
# existing ruleset scenarios. This will give the parsing capabilities of the
# code a good work out.
describe 'puppet resource firewall command' do
  before(:all) do
    # In order to properly check stderr for anomalies we need to fix the deprecation warnings from puppet.conf.
    config = run_shell('puppet config print config').stdout
    run_shell("sed -i -e 's/^templatedir.*$//' #{config}")
    if fetch_os_name == 'redhat' && [6, 7].include?(os[:release].to_i)
      run_shell('echo export LC_ALL="C" > /etc/profile.d/my-custom.lang.sh')
      run_shell('echo "## US English ##" >> /etc/profile.d/my-custom.lang.sh')
      run_shell('echo export LANG=en_US.UTF-8 >> /etc/profile.d/my-custom.lang.sh')
      run_shell('echo export LANGUAGE=en_US.UTF-8 >> /etc/profile.d/my-custom.lang.sh')
      run_shell('echo export LC_COLLATE=C >> /etc/profile.d/my-custom.lang.sh')
      run_shell('echo export LC_CTYPE=en_US.UTF-8 >> /etc/profile.d/my-custom.lang.sh')
      run_shell('source /etc/profile.d/my-custom.lang.sh')
    end
    run_shell('echo export LC_ALL="C" >> ~/.bashrc')
    run_shell('source ~/.bashrc || true')
  end

  context 'when make sure it returns no errors when executed on a clean machine' do
    before(:all) do
      iptables_flush_all_tables
      ip6tables_flush_all_tables
    end

    run_shell('locale')
    let(:result) { run_shell('puppet resource firewall') }

    it do
      # Don't check stdout, some boxes come with rules, that is normal
      run_shell('locale')
      expect(result.exit_code).to be_zero
      expect(result.stderr).to be_empty
    end
  end

  context 'when flush iptables and make sure it returns nothing afterwards' do
    before(:all) do
      iptables_flush_all_tables
      ip6tables_flush_all_tables
    end

    let(:result) { run_shell('puppet resource firewall') }

    it do
      # No rules, means no output thanks. And no errors as well.
      expect(result.exit_code).to be_zero
      expect(result.stdout).to eq "\n"
    end
  end

  context 'when accepts rules without comments' do
    before(:all) do
      iptables_flush_all_tables
      run_shell('iptables -A INPUT -j ACCEPT -p tcp --dport 80')
    end

    let(:result) { run_shell('puppet resource firewall') }

    it do
      # Don't check stdout, testing preexisting rules, output is normal
      expect(result.exit_code).to be_zero
      expect(result.stderr).to be_empty
    end
  end

  context 'when accepts rules with invalid comments' do
    before(:all) do
      iptables_flush_all_tables
      run_shell('iptables -A INPUT -j ACCEPT -p tcp --dport 80 -m comment --comment "http"')
    end

    let(:result) { run_shell('puppet resource firewall') }

    it do
      # Don't check stdout, testing preexisting rules, output is normal
      expect(result.exit_code).to be_zero
      expect(result.stderr).to be_empty
    end
  end

  context 'when accepts rules with multiple comments' do
    before(:all) do
      iptables_flush_all_tables
      run_shell('iptables -A INPUT -j ACCEPT -p tcp --dport 80 -m comment --comment "http" -m comment --comment "http"')
    end

    let(:result) { run_shell('puppet resource firewall') }

    it do
      # Don't check stdout, testing preexisting rules, output is normal
      expect(result.exit_code).to be_zero
      expect(result.stderr).to be_empty
    end
  end

  context 'when accepts rules with negation' do
    before :all do
      iptables_flush_all_tables
      run_shell('iptables -t nat -A POSTROUTING -s 192.168.122.0/24 ! -d 192.168.122.0/24 -p tcp -j MASQUERADE --to-ports 1024-65535')
      run_shell('iptables -t nat -A POSTROUTING -s 192.168.122.0/24 ! -d 192.168.122.0/24 -p udp -j MASQUERADE --to-ports 1024-65535')
      run_shell('iptables -t nat -A POSTROUTING -s 192.168.122.0/24 ! -d 192.168.122.0/24 -j MASQUERADE')
    end

    let(:result) { run_shell('puppet resource firewall') }

    it do
      # Don't check stdout, testing preexisting rules, output is normal
      expect(result.exit_code).to be_zero
      expect(result.stderr).to be_empty
    end
  end

  context 'when accepts rules with match extension tcp flag' do
    before :all do
      iptables_flush_all_tables
      run_shell('iptables -t mangle -A PREROUTING -d 1.2.3.4 -p tcp -m tcp -m multiport --dports 80,443,8140 -j MARK --set-mark 42')
    end

    let(:result) { run_shell('puppet resource firewall') }

    it do
      # Don't check stdout, testing preexisting rules, output is normal
      expect(result.exit_code).to be_zero
      expect(result.stderr).to be_empty
    end
  end

  context 'when accepts rules utilizing the statistic module' do
    before :all do
      iptables_flush_all_tables
      # This command doesn't work with all versions/oses, so let it fail
      run_shell('iptables -t nat -A POSTROUTING -d 1.2.3.4/32 -o eth0 -m statistic --mode nth --every 2 -j SNAT --to-source 2.3.4.5', expect_failures: true)
      run_shell('iptables -t nat -A POSTROUTING -d 1.2.3.4/32 -o eth0 -m statistic --mode nth --every 1 --packet 0 -j SNAT --to-source 2.3.4.6')
      run_shell('iptables -t nat -A POSTROUTING -d 1.2.3.4/32 -o eth0 -m statistic --mode random --probability 0.99 -j SNAT --to-source 2.3.4.7')
    end

    let(:result) { run_shell('puppet resource firewall') }

    it do
      # Don't check stdout, testing preexisting rules, output is normal
      expect(result.exit_code).to be_zero
      expect(result.stderr).to be_empty
    end
  end

  context 'when accepts rules with --dir' do
    before :all do
      iptables_flush_all_tables
      run_shell('iptables -t nat -A POSTROUTING -s 192.168.122.0/24 -m policy --dir out --pol ipsec -j ACCEPT')
      run_shell('iptables -t filter -A FORWARD -s 192.168.1.0/24 -d 192.168.122.0/24 -i eth0 -m policy --dir in --pol ipsec --reqid 108 --proto esp -j ACCEPT')
      run_shell('iptables -t filter -A FORWARD -s 192.168.122.0/24 -d 192.168.1.0/24 -o eth0 -m policy --dir out --pol ipsec --reqid 108 --proto esp -j ACCEPT')
      run_shell('iptables -t filter -A FORWARD -s 192.168.201.1/32 -d 192.168.122.0/24 -i eth0 -m policy --dir in --pol ipsec --reqid 107 --proto esp -j ACCEPT')
      run_shell('iptables -t filter -A FORWARD -s 192.168.122.0/24 -d 192.168.201.1/32 -o eth0 -m policy --dir out --pol ipsec --reqid 107 --proto esp -j ACCEPT')
    end

    let(:result) { run_shell('puppet resource firewall') }

    it do
      # Don't check stdout, testing preexisting rules, output is normal
      expect(result.exit_code).to be_zero
      expect(result.stderr).to be_empty
    end
  end

  context 'when accepts rules with -m (tcp|udp) without dport/sport' do
    before :all do
      iptables_flush_all_tables
      run_shell('iptables -A INPUT -s 10.0.0.0/8 -p udp -m udp -j ACCEPT')
    end

    let(:result) { run_shell('puppet resource firewall') }

    it do
      # Don't check stdout, testing preexisting rules, output is normal
      expect(result.exit_code).to be_zero
      expect(result.stderr).to be_empty
    end
  end

  context 'when accepts rules with -m ttl' do
    before :all do
      iptables_flush_all_tables
      run_shell('iptables -A FORWARD -m ttl --ttl-gt 100 -j LOG')
    end

    let(:result) { run_shell('puppet resource firewall') }

    it do
      # Don't check stdout, testing preexisting rules, output is normal
      puts "reslt = #{result}"
      puts "resltexit_code = #{result.exit_code}"
      puts "resltstderr = #{result.stderr}"
      expect(result.exit_code).to be_zero
      expect(result.stderr).to be_empty
    end
  end

  # ip6tables provider
  # TODO: Test below fails if this file is run seperately. i.e. bundle exec rspec spec/acceptance/resource_cmd_spec.rb
  context 'when dport/sport with ip6tables' do
    before :all do
      if os['family'] == 'debian'
        run_shell('echo "iptables-persistent iptables-persistent/autosave_v4 boolean false" | debconf-set-selections')
        run_shell('echo "iptables-persistent iptables-persistent/autosave_v6 boolean false" | debconf-set-selections')
        run_shell('apt-get install iptables-persistent -y')
      end
      ip6tables_flush_all_tables
      run_shell('ip6tables -A INPUT -d fe80::/64 -p tcp -m tcp --dport 546 --sport 547 -j ACCEPT -m comment --comment 000-foobar')
    end

    let(:result) { run_shell('puppet resource firewall \000-foobar\ provider=ip6tables') }

    it do
      # Don't check stdout, testing preexisting rules, output is normal
      expect(result.exit_code).to be_zero
      expect(result.stderr).to be_empty
    end
  end
end
