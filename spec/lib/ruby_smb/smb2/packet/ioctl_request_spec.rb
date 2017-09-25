require 'spec_helper'

RSpec.describe RubySMB::SMB2::Packet::IoctlRequest do
  subject(:packet) { described_class.new }

  it { is_expected.to respond_to :smb2_header }
  it { is_expected.to respond_to :structure_size }
  it { is_expected.to respond_to :ctl_code }
  it { is_expected.to respond_to :file_id }
  it { is_expected.to respond_to :input_offset }
  it { is_expected.to respond_to :input_count }
  it { is_expected.to respond_to :max_input_response }
  it { is_expected.to respond_to :output_offset }
  it { is_expected.to respond_to :output_count }
  it { is_expected.to respond_to :max_output_response }
  it { is_expected.to respond_to :flags }
  it { is_expected.to respond_to :buffer }

  it 'is little endian' do
    expect(described_class.fields.instance_variable_get(:@hints)[:endian]).to eq :little
  end

  describe '#smb2_header' do
    subject(:header) { packet.smb2_header }

    it 'is a standard SMB Header' do
      expect(header).to be_a RubySMB::SMB2::SMB2Header
    end

    it 'should have the command set to SMB_COM_IOCTL' do
      expect(header.command).to eq RubySMB::SMB2::Commands::IOCTL
    end

    it 'should not have the response flag set' do
      expect(header.flags.reply).to eq 0
    end
  end

  it 'should have a structure size of 57' do
    expect(packet.structure_size).to eq 57
  end

  describe '#file_id' do
    it 'should be an SMB FileID field' do
      expect(packet.file_id).to be_a RubySMB::Field::Smb2Fileid
    end
  end

  describe '#input_count' do
    it 'should be the size in bytes of the input buffer' do
      packet.buffer = 'hello'
      expect(packet.input_count).to eq 5
    end
  end

  describe '#input_offset' do
    it 'is set to 0 if the input buffer is empty' do
      expect(packet.input_offset).to eq 0
    end

    it 'is the absolute offset of the input buffer if the buffer is not empty' do
      packet.buffer = 'hello'
      expect(packet.input_offset).to eq packet.buffer.abs_offset
    end
  end

  describe '#flags' do
    subject(:flags) { packet.flags }

    describe '#is_fsctl' do
      it 'should be a 1-bit field per the SMB spec' do
        expect(flags.is_fsctl).to be_a BinData::Bit1
      end

      it_behaves_like 'bit field with one flag set', :is_fsctl, 'V', 0x00000001
    end
  end

end
