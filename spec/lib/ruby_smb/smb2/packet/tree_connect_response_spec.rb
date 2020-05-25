require 'spec_helper'

RSpec.describe RubySMB::SMB2::Packet::TreeConnectResponse do
  subject(:packet) { described_class.new }

  it { is_expected.to respond_to :smb2_header }
  it { is_expected.to respond_to :structure_size }
  it { is_expected.to respond_to :share_type }
  it { is_expected.to respond_to :share_flags }
  it { is_expected.to respond_to :capabilities }
  it { is_expected.to respond_to :maximal_access }

  it 'is little endian' do
    expect(described_class.fields.instance_variable_get(:@hints)[:endian]).to eq :little
  end

  describe '#smb2_header' do
    subject(:header) { packet.smb2_header }

    it 'is a standard SMB Header' do
      expect(header).to be_a RubySMB::SMB2::SMB2Header
    end

    it 'should have the command set to SMB_COM_NEGOTIATE' do
      expect(header.command).to eq RubySMB::SMB2::Commands::TREE_CONNECT
    end

    it 'should have the response flag set' do
      expect(header.flags.reply).to eq 1
    end
  end

  it 'reads a binary data as expected' do
    data = described_class.new
    expect(described_class.read(data.to_binary_s)).to eq(data)
  end
end
