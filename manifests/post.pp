# This creates all of the reject rules
class firewall::post {

  Firewall {
    require => Class['firewall::pre'],
  }
}
