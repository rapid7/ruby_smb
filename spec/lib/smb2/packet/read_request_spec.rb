require 'smb2'
require 'support/shared/examples/request'

describe Smb2::Packet::ReadRequest do
  subject(:packet) do
    described_class.new(data)
  end

  context 'with packet bytes' do
    let(:data) do
      [
        "fe534d4240000100000000000800010000000000000000000800000000000000" \
        "fffe000001000000190000000004000000000000000000000000000000000000" \
        "31005000000400000000000000000000250000000000000001000000ffffffff" \
        "0000000000000000000000000000000000"
      ].pack('H*')
    end

    it_behaves_like "request", Smb2::Commands::READ

    specify 'struct_size' do
      expect(packet.struct_size).to eq(49)
    end

    specify do
      expect(packet.flags).to eq(0)
    end

    specify 'read_length' do
      expect(packet.read_length).to eq(1024)
    end

    specify 'read_offset' do
      expect(packet.read_offset).to eq(0)
    end

    specify do
      expect(packet.file_id).to eq(["250000000000000001000000ffffffff"].pack('H*'))
    end

    specify 'read_channel_info things' do
      expect(packet.read_channel_info_offset).to eq(0)
      expect(packet.read_channel_info_length).to eq(0)
    end

    specify do
      expect(packet.channel).to eq(0)
    end

  end

end
