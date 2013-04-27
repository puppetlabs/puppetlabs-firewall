class firewall::linux::redhat (
  $ensure = running,
  $enable = true
) {
  service { 'iptables':
    ensure => $ensure,
    enable => $enable,
  }

  if $::operatingsystem == 'Fedora' and $::operatingsystemrelease == '18' {
    service { 'firewalld':
      ensure => stopped,
      enable => false,
    }
  }
}
