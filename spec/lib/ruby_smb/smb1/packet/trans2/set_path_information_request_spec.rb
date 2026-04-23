RSpec.describe RubySMB::SMB1::Packet::Trans2::SetPathInformationRequest do
  subject(:packet) { described_class.new }

  describe '#smb_header' do
    subject(:header) { packet.smb_header }

    it 'is a standard SMB Header' do
      expect(header).to be_a RubySMB::SMB1::SMBHeader
    end

    it 'should have the command set to SMB_COM_TRANSACTION2' do
      expect(header.command).to eq RubySMB::SMB1::Commands::SMB_COM_TRANSACTION2
    end

    it 'should not have the response flag set' do
      expect(header.flags.reply).to eq 0
    end
  end

  describe '#parameter_block' do
    subject(:parameter_block) { packet.parameter_block }

    it 'is a standard ParameterBlock' do
      expect(parameter_block).to be_a RubySMB::SMB1::Packet::Trans2::Request::ParameterBlock
    end

    it 'should have the setup set to the SET_PATH_INFORMATION subcommand' do
      expect(parameter_block.setup).to include RubySMB::SMB1::Packet::Trans2::Subcommands::SET_PATH_INFORMATION
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

      it { is_expected.to respond_to :information_level }
      it { is_expected.to respond_to :reserved }
      it { is_expected.to respond_to :filename }

      describe '#information_level' do
        it 'is a 16-bit field' do
          expect(parameters.information_level).to be_a BinData::Uint16le
        end
      end

      describe '#reserved' do
        it 'is a 32-bit field' do
          expect(parameters.reserved).to be_a BinData::Uint32le
        end
      end

      describe '#filename' do
        it 'is a BinData::Choice' do
          expect(parameters.filename).to be_a BinData::Choice
        end

        it 'encodes the filename as OEM when the unicode flag is cleared' do
          packet.smb_header.flags2.unicode = 0
          parameters.filename = 'link'
          expect(parameters.filename.to_binary_s).to eq "link\x00".b
        end

        it 'encodes the filename as UTF-16LE when the unicode flag is set' do
          packet.smb_header.flags2.unicode = 1
          parameters.filename = 'link'
          expect(parameters.filename.to_binary_s).to eq "link\x00".encode('UTF-16LE').b
        end
      end
    end

    describe '#trans2_data' do
      subject(:data) { data_block.trans2_data }

      it { is_expected.to respond_to :buffer }

      it 'carries an opaque byte buffer for the info-level-specific payload' do
        data.buffer = "target\x00"
        expect(data.buffer.to_binary_s).to eq "target\x00".b
      end
    end
  end

  describe 'encoded bytes for an SMB_SET_FILE_UNIX_LINK request' do
    it 'encodes the information level, filename and target in the expected positions' do
      packet.smb_header.flags2.unicode = 1
      packet.data_block.trans2_parameters.information_level =
        RubySMB::SMB1::Packet::Trans2::SetInformationLevel::SMB_SET_FILE_UNIX_LINK
      packet.data_block.trans2_parameters.filename = 'foo'
      packet.data_block.trans2_data.buffer = "bar\x00".encode('UTF-16LE')

      raw = packet.to_binary_s
      # Information level (little-endian 0x0201)
      expect(raw).to include("\x01\x02".b)
      # Filename in UTF-16LE with null terminator
      expect(raw).to include("foo\x00".encode('UTF-16LE').b)
      # Target in UTF-16LE with null terminator
      expect(raw).to include("bar\x00".encode('UTF-16LE').b)
    end
  end
end
