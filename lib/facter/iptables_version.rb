# frozen_string_literal: true

Facter.add(:iptables_version) do
  confine kernel: :Linux
  setcode do
    version = Facter::Core::Execution.execute('iptables --version')
    if version
      version.match(%r{\d+\.\d+\.\d+}).to_s
    else
      nil
    end
  end
end
