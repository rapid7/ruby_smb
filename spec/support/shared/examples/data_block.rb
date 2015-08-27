RSpec.shared_examples 'smb data block' do

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
end
