RSpec.describe RubySMB::SMB1::Packet::Trans2::QueryFsInformationResponse do
  subject(:packet) { described_class.new }

  describe '#smb_header' do
    subject(:header) { packet.smb_header }

    it 'is a standard SMB Header' do
      expect(header).to be_a RubySMB::SMB1::SMBHeader
    end

    it 'should have the command set to SMB_COM_TRANSACTION2' do
      expect(header.command).to eq RubySMB::SMB1::Commands::SMB_COM_TRANSACTION2
    end

    it 'should have the response flag set' do
      expect(header.flags.reply).to eq 1
    end
  end

  describe '#parameter_block' do
    subject(:parameter_block) { packet.parameter_block }

    it 'should have the setup set to the QUERY_FS_INFORMATION subcommand' do
      expect(parameter_block.setup).to include RubySMB::SMB1::Packet::Trans2::Subcommands::QUERY_FS_INFORMATION
    end
  end

  describe '#data_block' do
    subject(:data_block) { packet.data_block }

    it 'is a standard DataBlock' do
      expect(data_block).to be_a RubySMB::SMB1::DataBlock
    end

    it { is_expected.to respond_to :name }
    it { is_expected.to respond_to :trans2_parameters }
    it { is_expected.to respond_to :trans2_data }

    it 'should keep #trans2_parameters 4-byte aligned' do
      expect(data_block.trans2_parameters.abs_offset % 4).to eq 0
    end

    describe '#trans2_parameters' do
      subject(:parameters) { data_block.trans2_parameters }
    end

    describe '#trans2_data' do
      subject(:data) { data_block.trans2_data }

      it { is_expected.to respond_to :buffer }

      describe '#buffer' do
        it 'is a String field' do
          expect(data.buffer).to be_a BinData::String
        end
      end
    end
  end

end
