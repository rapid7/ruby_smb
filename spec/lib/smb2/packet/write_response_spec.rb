require 'smb2'

describe Smb2::Packet::WriteResponse do
  subject(:packet) do
    described_class.new(data)
  end

  context 'with srvsvc' do
    let(:data) do
      [
        "fe534d4240000100000000000900010001000000000000000700000000000000" \
        "fffe000001000000190000000004000000000000000000000000000000000000" \
        "11000000740000000000000000000000"
      ].pack('H*')
    end

    specify do
      expect(packet.struct_size).to eq(17)
      expect(packet.reserved).to eq(0)
      expect(packet.byte_count).to eq(116)
      expect(packet.remaining).to eq(0)

      expect(packet.channel_info_offset).to eq(0)
      expect(packet.channel_info_length).to eq(0)
      expect(packet.channel_info).to eq('')
    end
  end

end

