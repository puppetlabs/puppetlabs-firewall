require 'spec_helper_acceptance'

describe 'purge tests' do
  before :all do
    iptables_flush_all_tables
    ip6tables_flush_all_tables
  end

  context('when resources purge') do
    before(:all) do
      iptables_flush_all_tables

      shell('iptables -A INPUT -s 1.2.1.2')
      shell('iptables -A INPUT -s 1.2.1.2')
    end

    pp1 = <<-PUPPETCODE
        class { 'firewall': }
        resources { 'firewall':
          purge => true,
        }
    PUPPETCODE
    it 'make sure duplicate existing rules get purged' do
      apply_manifest(pp1, expect_changes: true)
    end

    it 'saves' do
      shell('iptables-save') do |r|
        expect(r.stdout).not_to match(%r{1\.2\.1\.2})
        expect(r.stderr).to eq('')
      end
    end
  end

  context('when ipv4 chain purge') do
    after(:all) do
      iptables_flush_all_tables
    end
    before(:each) do
      iptables_flush_all_tables

      shell('iptables -A INPUT -p tcp -s 1.2.1.1')
      shell('iptables -A INPUT -p udp -s 1.2.1.1')
      shell('iptables -A OUTPUT -s 1.2.1.2 -m comment --comment "010 output-1.2.1.2"')
    end

    pp2 = <<-PUPPETCODE
        class { 'firewall': }
        firewallchain { 'INPUT:filter:IPv4':
          purge => true,
        }
    PUPPETCODE
    it 'purges only the specified chain' do
      apply_manifest(pp2, expect_changes: true)

      shell('iptables-save') do |r|
        expect(r.stdout).to match(%r{010 output-1\.2\.1\.2})
        expect(r.stdout).not_to match(%r{1\.2\.1\.1})
        expect(r.stderr).to eq('')
      end
    end
    # rubocop:enable RSpec/ExampleLength

    pp3 = <<-PUPPETCODE
        class { 'firewall': }
        firewallchain { 'OUTPUT:filter:IPv4':
          purge => true,
        }
        firewall { '010 output-1.2.1.2':
          chain  => 'OUTPUT',
          proto  => 'all',
          source => '1.2.1.2',
        }
    PUPPETCODE
    it 'ignores managed rules' do
      apply_manifest(pp3, catch_changes: do_catch_changes)
    end

    pp4 = <<-PUPPETCODE
        class { 'firewall': }
        firewallchain { 'INPUT:filter:IPv4':
          purge => true,
          ignore => [
            '-s 1\.2\.1\.1',
          ],
        }
    PUPPETCODE
    it 'ignores specified rules' do
      apply_manifest(pp4, catch_changes: do_catch_changes)
    end

    pp5 = <<-PUPPETCODE
        class { 'firewall': }
        firewallchain { 'INPUT:filter:IPv4':
          purge => true,
          ignore => [
            '-s 1\.2\.1\.1',
          ],
        }
        firewall { '014 input-1.2.1.6':
          chain  => 'INPUT',
          proto  => 'all',
          source => '1.2.1.6',
        }
        -> firewall { '013 input-1.2.1.5':
          chain  => 'INPUT',
          proto  => 'all',
          source => '1.2.1.5',
        }
        -> firewall { '012 input-1.2.1.4':
          chain  => 'INPUT',
          proto  => 'all',
          source => '1.2.1.4',
        }
        -> firewall { '011 input-1.2.1.3':
          chain  => 'INPUT',
          proto  => 'all',
          source => '1.2.1.3',
        }
    PUPPETCODE
    it 'adds managed rules with ignored rules' do
      apply_manifest(pp5, catch_failures: true)

      expect(shell('iptables-save').stdout).to match(%r{-A INPUT -s 1\.2\.1\.1(\/32)? -p tcp\s?\n-A INPUT -s 1\.2\.1\.1(\/32)? -p udp})
    end
  end

  if default['platform'] !~ %r{el-5} && default['platform'] !~ %r{sles-10}
    context 'when ipv6 chain purge' do
      after(:all) do
        ip6tables_flush_all_tables
      end
      before(:each) do
        ip6tables_flush_all_tables

        shell('ip6tables -A INPUT -p tcp -s 1::42')
        shell('ip6tables -A INPUT -p udp -s 1::42')
        shell('ip6tables -A OUTPUT -s 1::50 -m comment --comment "010 output-1::50"')
      end

      pp6 = <<-PUPPETCODE
          class { 'firewall': }
          firewallchain { 'INPUT:filter:IPv6':
            purge => true,
          }
      PUPPETCODE
      it 'purges only the specified chain' do
        apply_manifest(pp6, expect_changes: true)

        shell('ip6tables-save') do |r|
          expect(r.stdout).to match(%r{010 output-1::50})
          expect(r.stdout).not_to match(%r{1::42})
          expect(r.stderr).to eq('')
        end
      end
      # rubocop:enable RSpec/ExampleLength

      pp7 = <<-PUPPETCODE
          class { 'firewall': }
          firewallchain { 'OUTPUT:filter:IPv6':
            purge => true,
          }
          firewall { '010 output-1::50':
            chain    => 'OUTPUT',
            proto    => 'all',
            source   => '1::50',
            provider => 'ip6tables',
          }
      PUPPETCODE
      it 'ignores managed rules' do
        apply_manifest(pp7, catch_changes: do_catch_changes)
      end

      pp8 = <<-PUPPETCODE
          class { 'firewall': }
          firewallchain { 'INPUT:filter:IPv6':
            purge => true,
            ignore => [
              '-s 1::42',
            ],
          }
      PUPPETCODE
      it 'ignores specified rules' do
        apply_manifest(pp8, catch_changes: do_catch_changes)
      end

      pp9 = <<-PUPPETCODE
          class { 'firewall': }
          firewallchain { 'INPUT:filter:IPv6':
            purge => true,
            ignore => [
              '-s 1::42',
            ],
          }
          firewall { '014 input-1::46':
            chain    => 'INPUT',
            proto    => 'all',
            source   => '1::46',
            provider => 'ip6tables',
          }
          -> firewall { '013 input-1::45':
            chain    => 'INPUT',
            proto    => 'all',
            source   => '1::45',
            provider => 'ip6tables',
          }
          -> firewall { '012 input-1::44':
            chain    => 'INPUT',
            proto    => 'all',
            source   => '1::44',
            provider => 'ip6tables',
          }
          -> firewall { '011 input-1::43':
            chain    => 'INPUT',
            proto    => 'all',
            source   => '1::43',
            provider => 'ip6tables',
          }
      PUPPETCODE
      it 'adds managed rules with ignored rules' do
        apply_manifest(pp9, catch_failures: true)

        expect(shell('ip6tables-save').stdout).to match(%r{-A INPUT -s 1::42(\/128)? -p tcp\s?\n-A INPUT -s 1::42(\/128)? -p udp})
      end
    end
  end
end
