firewall { '000 allow foo':
  dport => [7061, 7062],
  jump => "ACCEPT",
  proto => "tcp",
}

firewall { '001 allow boo':
  jump => "ACCEPT",
  iniface => "eth0",
  sport => "123",
  dport => "123",
  proto => "tcp",
  destination => "1.1.1.0/24",
  source => "2.2.2.0/24",
}

firewall { '999 bar':
  dport => "1233",
  proto => "tcp",
  jump => "DROP",
}

firewall { '002 foo':
  dport => "1233",
  proto => "tcp",
  jump => "DROP",
}

firewall { "010 icmp":
  proto => "icmp",
  icmp => "echo-reply",
  jump => "ACCEPT",
}

resources { 'firewall':
  purge => true
}

