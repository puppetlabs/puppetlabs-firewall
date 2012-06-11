# Class: firewall
#
# Manages the installation of packages for operating systems that are
#   currently supported by the firewall type.
#
class firewall {
  if ($::osfamily =~ /^(RedHat|Debian)$/) \
      or ($::operatingsystem =~ /^(RedHat|CentOS|Scientific|Debian|Ubuntu)$/) {
    package { 'iptables':
      ensure => present,
    }
  } else {
    fail('firewall: This OS is not currently supported')
  }
}
