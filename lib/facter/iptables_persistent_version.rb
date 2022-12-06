# frozen_string_literal: true

Facter.add(:iptables_persistent_version) do
  confine operatingsystem: ['Debian', 'Ubuntu']
  setcode do
    # Throw away STDERR because dpkg >= 1.16.7 will make some noise if the
    # package isn't currently installed.
    cmd = "dpkg-query -Wf '${Version}' netfilter-persistent 2>/dev/null"
    version = Facter::Core::Execution.execute(cmd, { on_fail: nil })

    if version.nil? || !version.match(%r{\d+\.\d+})
      nil
    else
      version
    end
  end
end
