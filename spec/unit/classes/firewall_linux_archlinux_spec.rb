# frozen_string_literal: true

require 'spec_helper'

describe 'firewall::linux::archlinux', type: :class do
  include_examples 'when ArchLinux'

  it {
    expect(subject).to contain_service('iptables').with(
      ensure: 'running',
      enable: 'true',
    )
  }

  it {
    expect(subject).to contain_service('ip6tables').with(
      ensure: 'running',
      enable: 'true',
    )
  }

  context 'with ensure => stopped' do
    let(:params) { { ensure: 'stopped' } }

    it {
      expect(subject).to contain_service('iptables').with(
        ensure: 'stopped',
      )
    }

    it {
      expect(subject).to contain_service('ip6tables').with(
        ensure: 'stopped',
      )
    }
  end

  context 'with enable => false' do
    let(:params) { { enable: 'false' } }

    it {
      expect(subject).to contain_service('iptables').with(
        enable: 'false',
      )
    }

    it {
      expect(subject).to contain_service('ip6tables').with(
        enable: 'false',
      )
    }
  end
end
