require 'spec_helper'

RSpec.describe RubySMB::SMB1::Packet::Trans2::SetFsInformationRequest do
  subject(:packet) { described_class.new }

  describe '#smb_header' do
    subject(:header) { packet.smb_header }

    it { is_expected.to be_a RubySMB::SMB1::SMBHeader }

    it 'has the command set to SMB_COM_TRANSACTION2' do
      expect(header.command).to eq RubySMB::SMB1::Commands::SMB_COM_TRANSACTION2
    end
  end

  describe '#parameter_block' do
    subject(:parameter_block) { packet.parameter_block }

    it { is_expected.to be_a RubySMB::SMB1::Packet::Trans2::Request::ParameterBlock }

    it 'uses the SET_FS_INFORMATION subcommand' do
      expect(parameter_block.setup[0]).to eq RubySMB::SMB1::Packet::Trans2::Subcommands::SET_FS_INFORMATION
    end
  end

  describe '#data_block' do
    subject(:data_block) { packet.data_block }

    it { is_expected.to respond_to :trans2_parameters }
    it { is_expected.to respond_to :trans2_data }

    describe '#trans2_parameters' do
      subject(:parameters) { data_block.trans2_parameters }

      it { is_expected.to respond_to :fid }
      it { is_expected.to respond_to :information_level }

      it 'is 4 bytes on the wire (fid + information_level)' do
        parameters.fid = 0
        parameters.information_level = RubySMB::SMB1::Packet::Trans2::SetFsInformationLevel::SMB_SET_CIFS_UNIX_INFO
        expect(parameters.to_binary_s.bytesize).to eq 4
      end
    end

    describe '#trans2_data' do
      it 'carries an opaque byte buffer whose contents depend on the information level' do
        data_block.trans2_data.buffer = "\x01\x00\x00\x00".b + "\x00".b * 8
        expect(data_block.trans2_data.buffer.bytesize).to eq 12
      end
    end
  end
end
