RSpec.describe RubySMB::SMB1::Packet::SMBDataBlock do

  subject(:data_block) { described_class.new }

  it { is_expected.to respond_to :byte_count }
  it { is_expected.to respond_to :bytes }

  describe 'byte_count' do
    it 'should be a 16-bit field per the SMB spec' do
      byte_count_size_field = data_block.fields.detect { |f| f.name == :byte_count}
      expect(byte_count_size_field.length).to eq 16
    end
  end

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