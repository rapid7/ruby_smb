RSpec.describe RubySMB::SMB1::Packet::AndXBlock do

  subject(:andx_block) { described_class.new }

  it { is_expected.to respond_to :andx_command }
  it { is_expected.to respond_to :andx_reserved }
  it { is_expected.to respond_to :andx_offset }

  describe 'andx_command' do
    it 'should be a 8-bit field per the SMB spec' do
      andx_command_size_field = andx_block.fields.detect { |f| f.name == :andx_command }
      expect(andx_command_size_field.length).to eq 8
    end

    it 'should be hardcoded to SMB_COM_NO_ANDX_COMMAND by default per the SMB spec' do
      expect(andx_block.andx_command).to eq RubySMB::SMB1::COMMANDS[:SMB_COM_NO_ANDX_COMMAND]
    end
  end

  describe 'andx_reserved' do
    it 'should be a 8-bit field per the SMB spec' do
      andx_reserved_size_field = andx_block.fields.detect { |f| f.name == :andx_reserved }
      expect(andx_reserved_size_field.length).to eq 8
    end

    it 'should be hardcoded to 0 by default per the SMB spec' do
      expect(andx_block.andx_reserved).to eq 0
    end
  end

  describe 'andx_offset' do
    it 'should be a 16-bit field per the SMB spec' do
      andx_offset_size_field = andx_block.fields.detect { |f| f.name == :andx_offset }
      expect(andx_offset_size_field.length).to eq 16
    end

    it 'should be hardcoded to 0 by default per the SMB spec' do
      expect(andx_block.andx_offset).to eq 0
    end
  end
end