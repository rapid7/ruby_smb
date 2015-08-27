RSpec.shared_examples 'smb parameter block' do

  it { is_expected.to respond_to :word_count }

  describe 'byte_count' do
    it 'should be a 8-bit field per the SMB spec' do
      expect(parameter_block.word_count).to be_a BinData::Uint8
    end

    it 'should equal the size of the rest of the block in words' do
      remaining_size = ((parameter_block.do_num_bytes - 1) /2).ceil
      expect(parameter_block.word_count).to eq remaining_size
    end
  end
end