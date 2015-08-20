require 'spec_helper'

RSpec.describe RubySMB::SMB1::Packet::SMBParameterBlock do

  subject(:param_block) { described_class.new }

  it { is_expected.to respond_to :word_count }
  it { is_expected.to respond_to :words }

  describe 'word_count' do
    it 'should be a 8-bit field per the SMB spec' do
      expect(param_block.word_count.num_bytes).to eq 1
    end
  end

  describe '#words=' do
    context 'with a valid value' do
      let(:words_value) { "\xFF\xFF\xFF\xFF" }

      it 'sets the word_count appropriately' do
        expect(param_block.word_count).to eq 0
        param_block.words = words_value
        expect(param_block.word_count).to eq 2
      end
    end

    context 'with an invalid value passed in' do
      let(:words_value) { 0xFFFFFFFF }

      it 'raises an ArgumentError' do
        expect{ param_block.words = words_value }.to raise_error BinData::ValidityError, "value '#{words_value}' not as expected for obj.words"
      end
    end
  end
end