RSpec.describe RubySMB::SMB1::Packet::SMBParameterBlock do

  subject(:param_block) { described_class.new }

  it { is_expected.to respond_to :word_count }
  it { is_expected.to respond_to :words }

  describe 'word_count' do
    it 'should be a 8-bit field per the SMB spec' do
      word_count_size_field = param_block.fields.detect { |f| f.name == :word_count}
      expect(word_count_size_field.length).to eq 8
    end
  end

  describe '#words=' do
    context 'with a valid value' do
      let(:words_value) { "\xFF\xFF\xFF\xFF" }

      it 'sets the word_count appropriately' do
        expect{ param_block.words = words_value }.to change{param_block.word_count}.to((words_value.size/2))
      end
    end

    context 'with an invalid value passed in' do
      let(:words_value) { 0xFFFFFFFF }

      it 'raises an ArgumentError' do
        expect{ param_block.words = words_value }.to raise_error ArgumentError, 'value must be a binary string'
      end
    end
  end
end