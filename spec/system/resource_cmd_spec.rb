require 'spec_helper_system'

# Here we want to test the the resource commands ability to work with different
# existing ruleset scenarios. This will give the parsing capabilities of the
# code a good work out.
describe 'puppet resource firewall command:' do
  it 'make sure it returns no errors when executed on a clean machine' do
    puppet_resource('firewall') do |r|
      r[:exit_code].should == 0
      # don't check stdout, some boxes come with rules, that is normal
      r[:stderr].should == ''
    end
  end

  it 'flush iptables and make sure it returns nothing afterwards' do
    iptables_flush_all_tables

    # No rules, means no output thanks. And no errors as well.
    puppet_resource('firewall') do |r|
      r[:exit_code].should == 0
      r[:stderr].should == ''
      r[:stdout].should == "\n"
    end
  end
end
