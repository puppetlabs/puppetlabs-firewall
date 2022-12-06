# frozen_string_literal: true

Facter.add(:iptables_version) do
  confine kernel: :Linux
  confine { Facter::Core::Execution.which('iptables') }
  setcode do
    version = Facter::Core::Execution.execute('iptables --version', { on_fail: nil })
    version.match(%r{\d+\.\d+\.\d+}).to_s if version
  end
end
