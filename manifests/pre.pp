# This creates all of the default rules
class firewall::pre {

  require firewall::service

  Firewall {
    before => Class['firewall::post'],
  }
}
