require 'spec_helper_system'

describe "firewall class:" do
  context 'no params:' do
    let(:pp) do
      pp = <<-EOS.gsub(/^\s{8}/,'')
        class { 'firewall': }
      EOS
    end

    it "should run without event" do
      puppet_apply(pp) do |r|
        r[:stderr].should == ''
        r[:exit_code].should_not eq(1)
      end
    end

    it "should be idempotent" do
      puppet_apply(pp) do |r|
        r[:stderr].should == ''
        r[:exit_code].should == 0
      end
    end
  end

  context 'ensure => stopped:' do
    let(:pp) do
      pp = <<-EOS.gsub(/^\s{8}/,'')
        class { 'firewall':
          ensure => stopped,
        }
      EOS
    end

    it "should run without event" do
      puppet_apply(pp) do |r|
        r[:stderr].should == ''
        r[:exit_code].should_not eq(1)
      end
    end

    it "should be idempotent" do
      puppet_apply(pp) do |r|
        r[:stderr].should == ''
        r[:exit_code].should == 0
      end
    end
  end

  context 'ensure => running:' do
    let(:pp) do
      pp = <<-EOS.gsub(/^\s{8}/,'')
        class { 'firewall':
          ensure => running,
        }
      EOS
    end

    it "should run without event" do
      puppet_apply(pp) do |r|
        r[:stderr].should == ''
        r[:exit_code].should_not eq(1)
      end
    end

    it "should be idempotent" do
      puppet_apply(pp) do |r|
        r[:stderr].should == ''
        r[:exit_code].should == 0
      end
    end
  end
end
