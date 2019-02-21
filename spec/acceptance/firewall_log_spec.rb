require 'spec_helper_acceptance'

describe 'log based tests' do
  before :all do
    iptables_flush_all_tables
    ip6tables_flush_all_tables
  end

  ppm2 = <<-PUPPETCODE
    firewall { '998 log all':
      proto     => 'all',
      jump      => 'LOG',
      log_level => 'debug',
    }
  PUPPETCODE
  values = [2, 0]
  it 'test log rule' do
    iptables_flush_all_tables

    values.each do |value|
      expect(apply_manifest(ppm2, catch_failures: true).exit_code).to eq(value)
    end
  end

  ppm3 = <<-PUPPETCODE
    firewall { '004 log all INVALID packets':
      chain      => 'INPUT',
      proto      => 'all',
      ctstate    => 'INVALID',
      jump       => 'LOG',
      log_level  => '3',
      log_prefix => 'IPTABLES dropped invalid: ',
    }
  PUPPETCODE
  ppm4 = <<-PUPPETCODE
    firewall { '003 log all INVALID packets':
      chain      => 'INPUT',
      proto      => 'all',
      ctstate    => 'INVALID',
      jump       => 'LOG',
      log_level  => '3',
      log_prefix => 'IPTABLES dropped invalid: ',
    }
  PUPPETCODE
  ppm5 = <<-PUPPETCODE + "\n" + ppm4
      resources { 'firewall':
        purge => true,
      }
  PUPPETCODE
  it 'test log rule - changing names' do
    iptables_flush_all_tables

    expect(apply_manifest(ppm3, catch_failures: true).exit_code).to eq(2)
    expect(apply_manifest(ppm5, catch_failures: true).exit_code).to eq(2)
  end

  ppm9 = <<-PUPPETCODE
    firewall { '004 log all INVALID packets':
      chain      => 'INPUT',
      proto      => 'all',
      ctstate    => 'INVALID',
      jump       => 'LOG',
      log_level  => '3',
      log_prefix => 'IPTABLES dropped invalid: ',
    }
  PUPPETCODE
  values = [2, 0]
  it 'test log rule - idempotent' do
    iptables_flush_all_tables

    values.each do |value|
      expect(apply_manifest(ppm9, catch_failures: true).exit_code).to eq(value)
    end
  end
end
