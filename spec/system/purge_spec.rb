require 'spec_helper_system'

describe "purge tests:" do
  context 'make sure duplicate existing rules get purged' do
    before :all do
      iptables_flush_all_tables

      shell('/sbin/iptables -A INPUT -s 1.2.1.2')
      shell('/sbin/iptables -A INPUT -s 1.2.1.2')
    end

    pp = <<-EOS
class { 'firewall': }
resources { 'firewall':
  purge => true,
}
    EOS

    context puppet_apply(pp) do
      its(:stderr) { should be_empty }
      its(:exit_code) { should == 2 }
    end

    context shell('/sbin/iptables-save') do
      its(:stdout) { should_not =~ /1\.2\.1\.2/ }
      its(:stderr) { should be_empty }
    end
  end
end
