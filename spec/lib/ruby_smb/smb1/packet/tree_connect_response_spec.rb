require 'spec_helper'

RSpec.describe RubySMB::SMB1::Packet::TreeConnectResponse do
  subject(:packet) { described_class.new }

  describe '#smb_header' do
    subject(:header) { packet.smb_header }

    it 'is a standard SMB Header' do
      expect(header).to be_a RubySMB::SMB1::SMBHeader
    end

    it 'should have the command set to SMB_COM_NEGOTIATE' do
      expect(header.command).to eq RubySMB::SMB1::Commands::SMB_COM_TREE_CONNECT
    end

    it 'should have the response flag set' do
      expect(header.flags.reply).to eq 1
    end
  end

  describe '#parameter_block' do
    subject(:parameter_block) { packet.parameter_block }

    it 'is a standard ParameterBlock' do
      expect(parameter_block).to be_a RubySMB::SMB1::ParameterBlock
    end

    it { is_expected.to respond_to :andx_block }
    it { is_expected.to respond_to :optional_support }
    it { is_expected.to respond_to :access_rights }
    it { is_expected.to respond_to :guest_access_rights }

    it 'has an AndXBlock' do
      expect(parameter_block.andx_block).to be_a RubySMB::SMB1::AndXBlock
    end
  end

  describe '#data_block' do
    subject(:data_block) { packet.data_block }

    it 'is a standard DataBlock' do
      expect(data_block).to be_a RubySMB::SMB1::DataBlock
    end

    it { is_expected.to respond_to :service }
    it { is_expected.to respond_to :native_file_system }
  end

  context 'when the connect is to a directory' do
    let(:directory_response) {
      packet = described_class.new
      packet.data_block.service = 'A:'
      packet
    }

    it 'returns a DirectoryAccessMask from #access_rights' do
      expect(directory_response.access_rights).to be_a RubySMB::SMB1::BitField::DirectoryAccessMask
    end

    it 'returns a DirectoryAccessMask from #guest_access_rights' do
      expect(directory_response.guest_access_rights).to be_a RubySMB::SMB1::BitField::DirectoryAccessMask
    end
  end

  context 'when the connect is to a named pipe' do
    let(:file_response) {
      packet = described_class.new
      packet.data_block.service = 'IPC'
      packet
    }

    it 'returns a FileAccessMask from #access_rights' do
      expect(file_response.access_rights).to be_a RubySMB::SMB1::BitField::FileAccessMask
    end

    it 'returns a FileAccessMask from #guest_access_rights' do
      expect(file_response.guest_access_rights).to be_a RubySMB::SMB1::BitField::FileAccessMask
    end
  end
end
