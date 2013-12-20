require 'spec_helper_acceptance'

describe "purge tests:" do
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
