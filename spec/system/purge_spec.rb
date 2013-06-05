require 'spec_helper_system'

describe "purge tests:" do
  it 'make sure duplicate existing rules get purged' do
    iptables_flush_all_tables

    shell('/sbin/iptables -A INPUT -s 1.2.1.2')
    shell('/sbin/iptables -A INPUT -s 1.2.1.2')
    pp = <<-EOS
class { 'firewall': }
resources { 'firewall':
  purge => true,
}
    EOS
    puppet_apply(pp) do |r|
      r.stderr.should be_empty
      r.exit_code.should == 2
    end

    system_run('/sbin/iptables-save') do |r|
      r.stdout.should_not =~ /1\.2\.1\.2/
      r.stderr.should be_empty
    end
  end
end
