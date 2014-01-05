require 'spec_helper_acceptance'

describe "purge tests:" do
  context('resources purge') do
    before(:all) do
      iptables_flush_all_tables

      shell('/sbin/iptables -A INPUT -s 1.2.1.2')
      shell('/sbin/iptables -A INPUT -s 1.2.1.2')
    end

    it 'make sure duplicate existing rules get purged' do

      pp = <<-EOS
        class { 'firewall': }
        resources { 'firewall':
          purge => true,
        }
      EOS

      expect(apply_manifest(pp, :catch_failures => true).exit_code).to eq(2)
    end

    it 'saves' do
      shell('/sbin/iptables-save') do |r|
        r.stdout.should_not =~ /1\.2\.1\.2/
        r.stderr.should be_empty
      end
    end
  end

  context('chain purge') do
    before(:each) do
      iptables_flush_all_tables

      shell('/sbin/iptables -A INPUT -s 1.2.1.1')
      shell('/sbin/iptables -A OUTPUT -s 1.2.1.2 -m comment --comment "010 output-1.2.1.2"')
    end

    it 'purges only the specified chain' do
      pp = <<-EOS
        class { 'firewall': }
        firewallchain { 'INPUT:filter:IPv4':
          purge => true,
        }
      EOS

      expect(apply_manifest(pp, :catch_failures => true).exit_code).to eq(2)

      shell('/sbin/iptables-save') do |r|
        r.stdout.should =~ /010 output-1\.2\.1\.2/
        r.stderr.should be_empty
      end
    end

    it 'ignores managed rules' do
      pp = <<-EOS
        class { 'firewall': }
        firewallchain { 'OUTPUT:filter:IPv4':
          purge => true,
        }
        firewall { '010 output-1.2.1.2':
          source => '1.2.1.2',
        }
      EOS

      expect(apply_manifest(pp, :catch_failures => true).exit_code).to eq(0)
    end

    it 'ignores specified rules' do
      pp = <<-EOS
        class { 'firewall': }
        firewallchain { 'INPUT:filter:IPv4':
          purge => true,
          ignore => [
            '-s 1\.2\.1\.1',
          ],
        }
      EOS

      expect(apply_manifest(pp, :catch_failures => true).exit_code).to eq(0)
    end
  end
end
