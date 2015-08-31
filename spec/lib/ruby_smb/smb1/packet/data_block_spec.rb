RSpec.describe RubySMB::SMB1::Packet::DataBlock do

  subject(:data_block) { described_class.new }

  it { is_expected.to respond_to :byte_count }

  describe 'byte_count' do
    it 'should be a 16-bit field per the SMB spec' do
      expect(data_block.byte_count).to be_a BinData::Uint16le
    end

    it 'should equal the size of the rest of the block in bytes' do
      remaining_size = data_block.do_num_bytes - 2
      expect(data_block.byte_count).to eq remaining_size
    end
  end

  it 'is little endian' do
    expect(described_class.fields.instance_variable_get(:@endian)).to eq :little
  end

end