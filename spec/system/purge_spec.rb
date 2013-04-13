require 'spec_helper_system'

describe "purge tests:" do
  it 'make sure duplicate existing rules get purged' do
    iptables_flush_all_tables

    system_run('iptables -A INPUT -s 1.2.1.2')
    system_run('iptables -A INPUT -s 1.2.1.2')
    pp = <<-EOS
resources { 'firewall':
  purge => true,
}
    EOS
    puppet_apply(pp) do |r|
      r[:stderr].should == ''
      r[:exit_code].should == 2
    end

    system_run('iptables-save') do |r|
      r[:stdout].should_not =~ /1\.2\.1\.2/
      r[:stderr].should == ''
    end
  end
end
