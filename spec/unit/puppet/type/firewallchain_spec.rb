# frozen_string_literal: true

require 'spec_helper'
require 'puppet/type/firewallchain'

RSpec.describe 'the firewallchain type' do
  it 'loads' do
    expect(Puppet::Type.type(:firewallchain)).not_to be_nil
  end
end
