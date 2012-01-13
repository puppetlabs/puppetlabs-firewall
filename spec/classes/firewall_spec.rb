#!/usr/bin/env rspec
require 'spec_helper'
include PuppetSpec::Files

describe 'firewall', :type => :class do

  before do
    @puppetdir = tmpdir('firewall')
    manifestdir = File.join(@puppetdir, 'manifests')
    Dir.mkdir(manifestdir)
    FileUtils.touch(File.join(manifestdir, 'site.pp'))
    Puppet[:confdir] = @puppetdir
  end

  after do
    FileUtils.remove_entry_secure(@puppetdir)
  end

  ## Same results will apply for CentOS & CloudLinux
  describe "RedHat generic tests" do
    let(:facts) {
      {
        :operatingsystem => 'RedHat',
        :kernel => 'Linux',
        :lsbmajdistrelease => 5,
      }
    }
    it { should contain_exec('firewall-persist') }
    it { should contain_file('/etc/sysconfig/ip6tables').with_mode('0600') }
    it { should contain_file('/etc/sysconfig/iptables').with_mode('0600') }
    it { should contain_package('iptables').with_ensure('present') }
    it { should contain_package('iptables-ipv6').with_ensure('present') }
    it { should contain_service('iptables').with_enable(true) }
    it { should contain_service('ip6tables').with_enable(true) }
  end

  ## Same results will apply for CentOS & CloudLinux
  describe "RedHat 5.x tests" do
    let(:facts) {
      {
        :operatingsystem => 'RedHat',
        :kernel => 'Linux',
        :lsbmajdistrelease => 5,
      }
    }
    it { should contain_exec('set-ipv6-iptables-policy') }
  end

  describe "Debian generic tests" do
    let(:facts) {
      {
        :operatingsystem => 'Debian',
        :kernel => 'Linux',
      }
    }
    it { should contain_exec('firewall-persist') }
    it { should contain_file('/etc/iptables/rules.v6').with_mode('0600') }
    it { should contain_service('iptables-persistent').with_enable(true) }
  end
  describe "Debian Lenny tests" do
    let(:facts) {
      {
        :operatingsystem => 'Debian',
        :kernel => 'Linux',
        :lsbmajdistrelease => 5,
      }
    }
    it { should contain_file('/etc/init.d/iptables-persistent') }
    it { should contain_file('/etc/iptables/rules.v4').with_mode('0600') }

  end
  describe "Debian Squeeze tests" do
    let(:facts) {
      {
        :operatingsystem => 'Debian',
        :kernel => 'Linux',
        :lsbmajdistrelease => 6,
      }
    }
    it { should contain_file('/etc/init.d/ip6tables-persistent') }
    it { should contain_file('/etc/iptables/rules').with_mode('0600') }
    it { should contain_package('iptables-persistent').with_ensure('present') }
    it { should contain_service('ip6tables-persistent').with_enable(true) }
  end
  describe "Debian Wheezy tests" do
    let(:facts) {
      {
        :operatingsystem => 'Debian',
        :kernel => 'Linux',
        :lsbmajdistrelease => 7,
      }
    }
    it { should contain_file('/etc/iptables/rules.v4').with_mode('0600') }
    it { should contain_file('/etc/iptables/rules.v6').with_mode('0600') }
    it { should contain_package('iptables-persistent').with_ensure('present') }
  end
end
