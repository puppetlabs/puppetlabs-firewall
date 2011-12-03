# These hashes allow us to iterate across a series of test data
# creating rspec examples for each parameter to ensure the input :line
# extrapolates to the desired value for the parameter in question. And
# vice-versa

# This hash is for testing a line conversion to a hash of parameters
# which will be used to create a resource.
ARGS_TO_HASH = {
  'long_rule_1' => {
    :line => '-A INPUT -s 1.1.1.1/32 -d 1.1.1.1/32 -p tcp -m multiport --dports 7061,7062 -m multiport --sports 7061,7062 -m comment --comment "000 allow foo" -j ACCEPT',
    :table => 'filter',
    :compare_all => true,
    :params => {
      :action => "accept",
      :chain => "INPUT",
      :destination => "1.1.1.1/32",
      :dport => ["7061","7062"],
      :ensure => :present,
      :line => '-A INPUT -s 1.1.1.1/32 -d 1.1.1.1/32 -p tcp -m multiport --dports 7061,7062 -m multiport --sports 7061,7062 -m comment --comment "000 allow foo" -j ACCEPT',
      :name => "000 allow foo",
      :proto => "tcp",
      :provider => "iptables",
      :source => "1.1.1.1/32",
      :sport => ["7061","7062"],
      :table => "filter",
    },
  },
  'action_drop_1' => {
    :line => '-A INPUT -m comment --comment "000 allow foo" -j DROP',
    :table => 'filter',
    :params => {
      :jump => nil,
      :action => "drop",
    },
  },
  'action_reject_1' => {
    :line => '-A INPUT -m comment --comment "000 allow foo" -j REJECT',
    :table => 'filter',
    :params => {
      :jump => nil,
      :action => "reject",
    },
  },
  'action_nil_1' => {
    :line => '-A INPUT -m comment --comment "000 allow foo"',
    :table => 'filter',
    :params => {
      :jump => nil,
      :action => nil,
    },
  },
  'jump_custom_chain_1' => {
    :line => '-A INPUT -m comment --comment "000 allow foo" -j custom_chain',
    :table => 'filter',
    :params => {
      :jump => "custom_chain",
      :action => nil,
    },
  },
  'dport_range_1' => {
    :line => '-A INPUT -m multiport --dports 1:1024 -m comment --comment "000 allow foo"',
    :table => 'filter',
    :params => {
      :dport => ["1-1024"],
    },
  },
  'dport_range_2' => {
    :line => '-A INPUT -m multiport --dports 15,512:1024 -m comment --comment "000 allow foo"',
    :table => 'filter',
    :params => {
      :dport => ["15","512-1024"],
    },
  },
  'sport_range_1' => {
    :line => '-A INPUT -m multiport --sports 1:1024 -m comment --comment "000 allow foo"',
    :table => 'filter',
    :params => {
      :sport => ["1-1024"],
    },
  },
  'sport_range_2' => {
    :line => '-A INPUT -m multiport --sports 15,512:1024 -m comment --comment "000 allow foo"',
    :table => 'filter',
    :params => {
      :sport => ["15","512-1024"],
    },
  },
  'state_returns_sorted_values' => {
    :line => '-A INPUT -m state --state INVALID,RELATED,ESTABLISHED',
    :table => 'filter',
    :params => {
      :state => ['ESTABLISHED', 'INVALID', 'RELATED'],
      :action => nil,
    },
  },
  'comment_string_character_validation' => {
    :line => '-A INPUT -s 192.168.0.1 -m comment --comment "000 allow from 192.168.0.1, please"',
    :table => 'filter',
    :params => {
      :source => '192.168.0.1',
    },
  },
  'log_level_debug' => {
    :line => '-A INPUT -m comment --comment "956 INPUT log-level" -m state --state NEW -j LOG --log-level 7',
    :table => 'filter',
    :params => {
      :state => ['NEW'],
      :log_level => '7',
      :jump => 'LOG'
    },
  },
  'log_level_warn' => {
    :line => '-A INPUT -m comment --comment "956 INPUT log-level" -m state --state NEW -j LOG',
    :table => 'filter',
    :params => {
      :state => ['NEW'],
      :log_level => '4',
      :jump => 'LOG'
    },
  },
  'load_limit_module' => {
    :line => '-A INPUT -m multiport --dports 123 -m comment --comment "057 INPUT limit NTP" -m limit --limit 15/hour',
    :table => 'filter',
    :params => {
      :dport => ['123'],
      :limit => '15/hour'
    },
  },
  'proto_ipencap' => {
    :line => '-A INPUT -p ipencap -m comment --comment "0100 INPUT accept ipencap"',
    :table => 'filter',
    :params => {
      :proto => 'ipencap',
    }
  },
  'load_uid_owner_filter_module' => {
    :line => '-A OUTPUT -m owner --uid-owner root -m comment --comment "057 OUTPUT uid root only" -j ACCEPT',
    :table => 'filter',
    :params => {
      :action => 'accept',
      :uid => 'root',
      :chain => 'OUTPUT',
    },
  },
  'load_uid_owner_postrouting_module' => {
    :line => '-t mangle -A POSTROUTING -m owner --uid-owner root -m comment --comment "057 POSTROUTING uid root only" -j ACCEPT',
    :table => 'mangle',
    :params => {
      :action => 'accept',
      :chain => 'POSTROUTING',
      :uid => 'root',
    },
  },
  'load_gid_owner_filter_module' => {
    :line => '-A OUTPUT -m owner --gid-owner root -m comment --comment "057 OUTPUT gid root only" -j ACCEPT',
    :table => 'filter',
    :params => {
      :action => 'accept',
      :chain => 'OUTPUT',
      :gid => 'root',
    },
  },
  'load_gid_owner_postrouting_module' => {
    :line => '-t mangle -A POSTROUTING -m owner --gid-owner root -m comment --comment "057 POSTROUTING gid root only" -j ACCEPT',
    :table => 'mangle',
    :params => {
      :action => 'accept',
      :chain => 'POSTROUTING',
      :gid => 'root',
    },
  },
}

# This hash is for testing converting a hash to an argument line.
HASH_TO_ARGS = {
  'long_rule_1' => {
    :params => {
      :action => "accept",
      :chain => "INPUT",
      :destination => "1.1.1.1",
      :dport => ["7061","7062"],
      :ensure => :present,
      :name => "000 allow foo",
      :proto => "tcp",
      :source => "1.1.1.1",
      :sport => ["7061","7062"],
      :table => "filter",
    },
    :args => ["-t", :filter, "-s", "1.1.1.1/32", "-d", "1.1.1.1/32", "-p", :tcp, "-m", "multiport", "--sports", "7061,7062", "-m", "multiport", "--dports", "7061,7062", "-m", "comment", "--comment", "000 allow foo", "-j", "ACCEPT"],
  },
  'long_rule_2' => {
    :params => {
      :chain => "INPUT",
      :destination => "2.10.13.3/24",
      :dport => ["7061"],
      :ensure => :present,
      :jump => "my_custom_chain",
      :name => "700 allow bar",
      :proto => "udp",
      :source => "1.1.1.1",
      :sport => ["7061","7062"],
      :table => "filter",
    },
    :args => ["-t", :filter, "-s", "1.1.1.1/32", "-d", "2.10.13.0/24", "-p", :udp, "-m", "multiport", "--sports", "7061,7062", "-m", "multiport", "--dports", "7061", "-m", "comment", "--comment", "700 allow bar", "-j", "my_custom_chain"],
  },
  'no_action' => {
    :params => {
      :name => "100 no action",
      :table => "filter",
    },
    :args => ["-t", :filter, "-p", :tcp, "-m", "comment", "--comment",
      "100 no action"],
  },
  'sport_range_1' => {
    :params => {
      :name => "100 sport range",
      :sport => ["1-1024"],
      :table => "filter",
    },
    :args => ["-t", :filter, "-p", :tcp, "-m", "multiport", "--sports", "1:1024", "-m", "comment", "--comment", "100 sport range"],
  },
  'sport_range_2' => {
    :params => {
      :name => "100 sport range",
      :sport => ["15","512-1024"],
      :table => "filter",
    },
    :args => ["-t", :filter, "-p", :tcp, "-m", "multiport", "--sports", "15,512:1024", "-m", "comment", "--comment", "100 sport range"],
  },
  'dport_range_1' => {
    :params => {
      :name => "100 sport range",
      :dport => ["1-1024"],
      :table => "filter",
    },
    :args => ["-t", :filter, "-p", :tcp, "-m", "multiport", "--dports", "1:1024", "-m", "comment", "--comment", "100 sport range"],
  },
  'dport_range_2' => {
    :params => {
      :name => "100 sport range",
      :dport => ["15","512-1024"],
      :table => "filter",
    },
    :args => ["-t", :filter, "-p", :tcp, "-m", "multiport", "--dports", "15,512:1024", "-m", "comment", "--comment", "100 sport range"],
  },
  'states_set_from_array' => {
    :params => {
      :name => "100 states_set_from_array",
      :table => "filter",
      :state => ['ESTABLISHED', 'INVALID']
    },
    :args => ["-t", :filter, "-p", :tcp, "-m", "comment", "--comment", "100 states_set_from_array",
      "-m", "state", "--state", "ESTABLISHED,INVALID"],
  },
  'comment_string_character_validation' => {
    :params => {
      :name => "000 allow from 192.168.0.1, please",
      :table => 'filter',
      :source => '192.168.0.1'
    },
    :args => ['-t', :filter, '-s', '192.168.0.1/32', '-p', :tcp, '-m', 'comment', '--comment', '000 allow from 192.168.0.1, please'],
  },
  'port_property' => {
    :params => {
      :name => '001 port property',
      :table => 'filter',
      :port => '80',
    },
    :args => ['-t', :filter, '-p', :tcp, '-m', 'multiport', '--ports', '80', '-m', 'comment', '--comment', '001 port property'],
  },
  'log_level_debug' => {
    :params => {
      :name => '956 INPUT log-level',
      :table => 'filter',
      :state => 'NEW',
      :jump => 'LOG',
      :log_level => 'debug'
    },
    :args => ['-t', :filter, '-p', :tcp, '-m', 'comment', '--comment', '956 INPUT log-level', '-m', 'state', '--state', 'NEW', '-j', 'LOG', '--log-level', '7'],
  },
  'log_level_warn' => {
    :params => {
      :name => '956 INPUT log-level',
      :table => 'filter',
      :state => 'NEW',
      :jump => 'LOG',
      :log_level => 'warn'
    },
    :args => ['-t', :filter, '-p', :tcp, '-m', 'comment', '--comment', '956 INPUT log-level', '-m', 'state', '--state', 'NEW', '-j', 'LOG', '--log-level', '4'],
  },
  'load_limit_module' => {
    :params => {
      :name => '057 INPUT limit NTP',
      :table => 'filter',
      :dport => '123',
      :limit => '15/hour'
    },
    :args => ['-t', :filter, '-p', :tcp, '-m', 'multiport', '--dports', '123', '-m', 'comment', '--comment', '057 INPUT limit NTP', '-m', 'limit', '--limit', '15/hour'],
  },
  'proto_ipencap' => {
    :params => {
      :name => '0100 INPUT accept ipencap',
      :table => 'filter',
      :proto => 'ipencap',
    },
    :args => ['-t', :filter, '-p', :ipencap, '-m', 'comment', '--comment', '0100 INPUT accept ipencap'],
  },
  'load_uid_owner_filter_module' => {
    :params => {
      :name => '057 OUTPUT uid root only',
      :table => 'filter',
      :uid => 'root',
      :action => 'accept',
      :chain => 'OUTPUT',
      :proto => 'all',
    },
    :args => ['-t', :filter, '-p', :all, '-m', 'owner', '--uid-owner', 'root', '-m', 'comment', '--comment', '057 OUTPUT uid root only', '-j', 'ACCEPT'],
  },
  'load_uid_owner_postrouting_module' => {
    :params => {
      :name => '057 POSTROUTING uid root only',
      :table => 'mangle',
      :uid => 'root',
      :action => 'accept',
      :chain => 'POSTROUTING',
      :proto => 'all',
    },
    :args => ['-t', :mangle, '-p', :all, '-m', 'owner', '--uid-owner', 'root', '-m', 'comment', '--comment', '057 POSTROUTING uid root only', '-j', 'ACCEPT'],
  },
  'load_gid_owner_filter_module' => {
    :params => {
      :name => '057 OUTPUT gid root only',
      :table => 'filter',
      :chain => 'OUTPUT',
      :gid => 'root',
      :action => 'accept',
      :proto => 'all',
    },
    :args => ['-t', :filter, '-p', :all, '-m', 'owner', '--gid-owner', 'root', '-m', 'comment', '--comment', '057 OUTPUT gid root only', '-j', 'ACCEPT'],
  },
  'load_gid_owner_postrouting_module' => {
    :params => {
      :name => '057 POSTROUTING gid root only',
      :table => 'mangle',
      :gid => 'root',
      :action => 'accept',
      :chain => 'POSTROUTING',
      :proto => 'all',
    },
    :args => ['-t', :mangle, '-p', :all, '-m', 'owner', '--gid-owner', 'root', '-m', 'comment', '--comment', '057 POSTROUTING gid root only', '-j', 'ACCEPT'],
  },
}
