require 'spec_helper_system'

describe "firewall class:" do
  it "should run without event" do
    pp = <<-EOS
      class { 'firewall': }
    EOS
    puppet_apply(pp) do |r|
      r[:stderr].should == ''
      r[:exit_code].should_not eq(1)
    end
  end

  it "should be idempotent" do
    pp = <<-EOS
      class { 'firewall': }
    EOS
    puppet_apply(pp) do |r|
      r[:stderr].should == ''
      r[:exit_code].should == 0
    end
  end
end
