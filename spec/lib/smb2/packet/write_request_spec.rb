require 'smb2'

describe Smb2::Packet::WriteRequest do
  subject(:packet) do
    described_class.new(data)
  end

  context 'with srvsvc' do
    let(:data) do
      [
        "fe534d4240000100000000000900010000000000000000000700000000000000" \
        "fffe000001000000190000000004000000000000000000000000000000000000" \
        "31007000740000000000000000000000250000000000000001000000ffffffff" \
        "0000000000000000000000000000000005000b03100000007400000002000000" \
        "b810b810000000000200000000000100c84f324b7016d30112785a47bf6ee188" \
        "03000000045d888aeb1cc9119fe808002b1048600200000001000100c84f324b" \
        "7016d30112785a47bf6ee188030000002c1cb76c129840450300000000000000" \
        "01000000"
      ].pack('H*')
    end

    specify do
      expect(packet.struct_size).to eq(49)
      expect(packet.data_offset).to eq(0x0070)
      expect(packet.data_length).to eq(116)
      expect(packet.file_offset).to eq(0)
      expect(packet.file_id).to eq(["250000000000000001000000ffffffff"].pack('H*'))
      expect(packet.channel).to eq(0)
      expect(packet.remaining_bytes).to eq(0)
      expect(packet.channel_info_offset).to eq(0)
      expect(packet.channel_info_length).to eq(0)
      expect(packet.flags).to eq(0)
    end
  end

end


