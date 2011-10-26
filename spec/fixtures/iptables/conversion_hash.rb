# These hashes allow us to iterate across a series of test data
# creating rspec examples for each parameter to ensure the input :line
# extrapolates to the desired value for the parameter in question. And
# vice-versa

# This hash is for testing a line conversion to a hash of parameters
# which will be used to create a resource.
ARGS_TO_HASH = { 
  'long_rule_1' => {
    :line => '-A INPUT -s 1.1.1.1 -d 1.1.1.1 -p tcp -m multiport --dports 7061,7062 -m multiport --sports 7061,7062 -m comment --comment "000 allow foo" -j ACCEPT',
    :table => 'filter',
    :compare_all => true,
    :params => {
      :action => "accept",
      :chain => "INPUT",
      :destination => "1.1.1.1",
      :dport => ["7061","7062"],
      :ensure => :present,
      :line => '-A INPUT -s 1.1.1.1 -d 1.1.1.1 -p tcp -m multiport --dports 7061,7062 -m multiport --sports 7061,7062 -m comment --comment "000 allow foo" -j ACCEPT',
      :name => "000 allow foo",
      :proto => "tcp",
      :provider => "iptables",
      :source => "1.1.1.1",
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
    :args => ["-t", :filter, "-s", "1.1.1.1", "-d", "1.1.1.1", "-p", :tcp, "-m", "multiport", "--sports", "7061,7062", "-m", "multiport", "--dports", "7061,7062", "-m", "comment", "--comment", "000 allow foo", "-j", "ACCEPT"],
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
    :args => ["-t", :filter, "-s", "1.1.1.1", "-d", "2.10.13.3/24", "-p", :udp, "-m", "multiport", "--sports", "7061,7062", "-m", "multiport", "--dports", "7061", "-m", "comment", "--comment", "700 allow bar", "-j", "my_custom_chain"],
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
}
