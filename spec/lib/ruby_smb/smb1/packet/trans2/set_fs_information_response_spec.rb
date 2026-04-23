require 'spec_helper'

RSpec.describe RubySMB::SMB1::Packet::Trans2::SetFsInformationResponse do
  subject(:packet) { described_class.new }

  describe '#smb_header' do
    subject(:header) { packet.smb_header }

    it { is_expected.to be_a RubySMB::SMB1::SMBHeader }

    it 'has the command set to SMB_COM_TRANSACTION2' do
      expect(header.command).to eq RubySMB::SMB1::Commands::SMB_COM_TRANSACTION2
    end

    it 'sets the reply flag' do
      expect(header.flags.reply).to eq 1
    end
  end

  describe '#parameter_block' do
    subject(:parameter_block) { packet.parameter_block }

    it { is_expected.to be_a RubySMB::SMB1::Packet::Trans2::Response::ParameterBlock }

    it 'uses the SET_FS_INFORMATION subcommand' do
      expect(parameter_block.setup[0]).to eq RubySMB::SMB1::Packet::Trans2::Subcommands::SET_FS_INFORMATION
    end
  end
end
