#
#This class manages iptables on redhat
class firewall::linux::redhat (
  $ensure = running,
  $enable = true
) {
  service { 'iptables':
    ensure    => $ensure,
    enable    => $enable,
    hasstatus => true,
  }
}
