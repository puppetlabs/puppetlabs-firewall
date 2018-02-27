require 'spec_helper'

describe 'firewall::linux::archlinux', type: :class do
  let(:facts) do
    {
      osfamily: 'Archlinux',
      operatingsystem: 'Archlinux',
    }
  end

  it {
    is_expected.to contain_service('firewall').with(
      ensure: 'running',
      enable: 'true',
    )
  }
  it {
    is_expected.to contain_service('firewall6').with(
      ensure: 'running',
      enable: 'true',
    )
  }

  context 'with ensure => stopped' do
    let(:params) { { ensure: 'stopped' } }

    it {
      is_expected.to contain_service('firewall').with(
        ensure: 'stopped',
      )
    }
    it {
      is_expected.to contain_service('firewall6').with(
        ensure: 'stopped',
      )
    }
  end

  context 'with enable => false' do
    let(:params) { { enable: 'false' } }

    it {
      is_expected.to contain_service('firewall').with(
        enable: 'false',
      )
    }
    it {
      is_expected.to contain_service('firewall6').with(
        enable: 'false',
      )
    }
  end
end
