require 'spec_helper'

RSpec.describe RubySMB::Smb1::Packet::SmbParameterBlock do

  subject(:param_block) { described_class.new }

  it { is_expected.to respond_to :word_count }
  it { is_expected.to respond_to :words }
end