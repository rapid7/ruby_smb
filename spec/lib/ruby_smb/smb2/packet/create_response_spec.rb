require 'spec_helper'

RSpec.describe RubySMB::SMB2::Packet::CreateResponse do
  subject(:packet) { described_class.new }

  it { is_expected.to respond_to :smb2_header }
  it { is_expected.to respond_to :structure_size }

  it 'is little endian' do
    expect(described_class.fields.instance_variable_get(:@hints)[:endian]).to eq :little
  end

  describe '#smb2_header' do
    subject(:header) { packet.smb2_header }

    it 'is a standard SMB Header' do
      expect(header).to be_a RubySMB::SMB2::SMB2Header
    end

    it 'should have the command set to SMB_COM_NEGOTIATE' do
      expect(header.command).to eq RubySMB::SMB2::Commands::CREATE
    end

    it 'should have the response flag set' do
      expect(header.flags.reply).to eq 1
    end
  end

  it 'should have a structure size of 89' do
    expect(packet.structure_size).to eq 89
  end

  it 'tracks the creation time in a Filetime field' do
    expect(packet.create_time).to be_a RubySMB::Field::FileTime
  end

  it 'tracks the last access time in a Filetime field' do
    expect(packet.last_access).to be_a RubySMB::Field::FileTime
  end

  it 'tracks the last write time in a Filetime field' do
    expect(packet.last_write).to be_a RubySMB::Field::FileTime
  end

  it 'tracks the last modified time in a Filetime field' do
    expect(packet.last_change).to be_a RubySMB::Field::FileTime
  end

  it 'contains the file attributes of the file' do
    expect(packet.file_attributes).to be_a RubySMB::Fscc::FileAttributes
  end

  it 'has the handles to the file in an SMB2_FILEID' do
    expect(packet.file_id).to be_a RubySMB::Field::Smb2Fileid
  end

  describe '#contexts' do
    # with no context, the offset and length should be 0
    # see: https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/d166aa9e-0b53-410e-b35e-3933d8131927
    it 'should have the contexts_offset set to 0' do
      expect(packet.contexts_offset).to eq 0
    end

    it 'should have the contexts_length set to ' do
      expect(packet.contexts_length).to eq 0
    end
  end
end
