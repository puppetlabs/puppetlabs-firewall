require 'spec_helper'

describe 'actual.resource' do
  with_debian_facts

  it { is_expected.to compile }
end
