require 'spec_helper'

RSpec.describe RubySMB::Smb1::Packet::SmbDataBlock do

  subject(:data_block) { described_class.new }

  it { is_expected.to respond_to :byte_count }
  it { is_expected.to respond_to :bytes }

  describe '#bytes=' do
    context 'with a valid value' do
      let(:bytes_value) { "\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF" }

      it 'sets the byte_count appropriately' do
        expect{ data_block.bytes = bytes_value }.to change{data_block.byte_count}.to((bytes_value.size))
      end
    end

    context 'with an invalid value passed in' do
      let(:bytes_value) { 0xFFFFFFFF_FFFFFFFF }

      it 'raises an ArgumentError' do
        expect{ data_block.bytes = bytes_value }.to raise_error ArgumentError, 'value must be a binary string'
      end
    end
  end
end