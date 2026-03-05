# frozen_string_literal: true

require 'spec_helper'

describe 'firewall::linux::debian', type: :class do
  context 'with Debian 11' do
    include_examples 'when Debian 11'

    it {
      expect(subject).to contain_package('iptables-persistent').with(
        ensure: 'installed',
      )
    }

    it {
      expect(subject).to contain_service('netfilter-persistent').with(
        ensure: 'running',
        enable: 'true',
        require: 'Package[iptables-persistent]',
      )
    }
  end

  context 'with Debian 11, enable => false' do
    let(:params) { { enable: 'false' } }

    include_examples 'when Debian 11'

    it {
      expect(subject).to contain_service('netfilter-persistent').with(
        enable: 'false',
      )
    }
  end

  context 'with Debian 11, ensure => stopped' do
    let(:params) { { ensure: 'stopped' } }

    include_examples 'when Debian 11'

    it {
      expect(subject).to contain_service('netfilter-persistent').with(
        ensure: 'stopped',
      )
    }
  end

  context 'with Debian 12' do
    include_examples 'when Debian 12'

    it {
      expect(subject).to contain_package('iptables-persistent').with(
        ensure: 'installed',
      )
    }

    it {
      expect(subject).to contain_service('netfilter-persistent').with(
        ensure: 'running',
        enable: 'true',
        require: 'Package[iptables-persistent]',
      )
    }
  end

  context 'with Debian 12, enable => false' do
    let(:params) { { enable: 'false' } }

    include_examples 'when Debian 12'

    it {
      expect(subject).to contain_service('netfilter-persistent').with(
        enable: 'false',
      )
    }
  end

  context 'with Debian 12, ensure => stopped' do
    let(:params) { { ensure: 'stopped' } }

    include_examples 'when Debian 12'

    it {
      expect(subject).to contain_service('netfilter-persistent').with(
        ensure: 'stopped',
      )
    }
  end

  context 'with Debian unstable' do
    include_examples 'when Debian Unstable'

    it {
      expect(subject).to contain_package('netfilter-persistent').with(
        ensure: 'installed',
      )
    }

    it {
      expect(subject).to contain_service('netfilter-persistent').with(
        ensure: 'running',
        enable: 'true',
        require: 'Package[netfilter-persistent]',
      )
    }
  end

  context 'with Debian unstable, enable => false' do
    let(:params) { { enable: 'false' } }

    include_examples 'when Debian Unstable'

    it {
      expect(subject).to contain_service('netfilter-persistent').with(
        enable: 'false',
      )
    }
  end

  context 'with Debian unstable, ensure => stopped' do
    let(:params) { { ensure: 'stopped' } }

    include_examples 'when Debian Unstable'

    it {
      expect(subject).to contain_service('netfilter-persistent').with(
        ensure: 'stopped',
      )
    }
  end
end
