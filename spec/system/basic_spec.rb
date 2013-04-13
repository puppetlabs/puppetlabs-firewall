require 'spec_helper_system'

# Here we put the more basic fundamental tests, ultra obvious stuff.
describe "basic tests:" do
  it 'make sure we have copied the module across' do
    # No point diagnosing any more if the module wasn't copied properly
    system_run("ls /etc/puppet/modules/firewall") do |r|
      r[:exit_code].should == 0
      r[:stdout].should =~ /Modulefile/
      r[:stderr].should == ''
    end
  end
end
