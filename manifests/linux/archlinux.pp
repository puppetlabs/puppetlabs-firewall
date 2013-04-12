class firewall::linux::archlinux {
  service { 'iptables':
    ensure => running,
    enable => true,
  }

  service { 'ip6tables':
    ensure => running,
    enable => true,
  }

  file { '/etc/iptables/iptables.rules':
    ensure => present,
    before => Service['iptables'],
  }

  file { '/etc/iptables/ip6tables.rules':
    ensure => present,
    before => Service['ip6tables'],
  }
}
