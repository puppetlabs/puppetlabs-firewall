require 'spec_helper_system'

describe "param based tests:" do
  def pp(params)
    name = params.delete('name') || '100 test'
    pm = <<-EOS
firewall { '#{name}':
    EOS

    params.each do |k,v| 
      pm += <<-EOS
  #{k} => #{v},
      EOS
    end

    pm += <<-EOS
}
    EOS
    pm
  end

  it 'test various params' do
    facts = system_node.facts

    unless (facts['operatingsystem'] == 'CentOS') && \
      facts['operatingsystemrelease'] =~ /^5\./ then

      iptables_flush_all_tables

      ppm = pp({
        'table' => "'raw'",
        'socket' => 'true',
        'chain' => "'PREROUTING'",
        'jump' => 'LOG',
        'log_level' => 'debug',
      })
      puppet_apply(ppm) do |r|
        r[:stderr].should == ''
        r[:exit_code].should == 2
      end

      # check idempotency
      puppet_apply(ppm) do |r|
        r[:stderr].should == ''
        r[:exit_code].should == 0
      end
    end
  end

  it 'test log rule' do
    iptables_flush_all_tables

    ppm = pp({
      'name' => '998 log all',
      'proto' => 'all',
      'jump' => 'LOG',
      'log_level' => 'debug',
    })
    puppet_apply(ppm) do |r|
      r.stderr.should == ''
      r.exit_code.should == 2
    end

    # check idempotency
    puppet_apply(ppm) do |r|
      r.stderr.should == ''
      r.exit_code.should == 0
    end
  end

  it 'test log rule - changing names' do
    iptables_flush_all_tables

    ppm1 = pp({
      'name' => '004 log all INVALID packets',
      'chain' => 'INPUT',
      'proto' => 'all',
      'state' => 'INVALID',
      'jump' => 'LOG',
      'log_level' => 'debug',
    })

    ppm2 = pp({
      'name' => '003 log all INVALID packets',
      'chain' => 'INPUT',
      'proto' => 'all',
      'state' => 'INVALID',
      'jump' => 'LOG',
      'log_level' => 'debug',
    })

    puppet_apply(ppm1) do |r|
      r.stderr.should == ''
      r.exit_code.should == 2
    end

    puppet_apply(ppm1) do |r|
      r.stderr.should == ''
      r.exit_code.should == 0
    end

    # check idempotency
    ppm = <<-EOS + "\n" + ppm2
      resources { 'firewall':
        purge => true,
      }
    EOS
    puppet_apply(ppm) do |r|
      r.stderr.should == ''
      r.exit_code.should == 2
    end
  end
end
