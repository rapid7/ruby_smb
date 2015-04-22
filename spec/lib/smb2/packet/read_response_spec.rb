require 'smb2'

RSpec.describe Smb2::Packet::ReadResponse do
  subject(:packet) do
    described_class.new(data)
  end

  context 'when parsing a packet' do
    let(:data) do
      [
        "fe534d4240000100000000000800010001000000000000000800000000000000" \
        "fffe000001000000190000000004000000000000000000000000000000000000" \
        "110050005c000000000000000000000005000c03100000005c00000002000000" \
        "b810b8104a1e00000d005c504950455c73727673766300000200000000000000" \
        "045d888aeb1cc9119fe808002b10486002000000030003000000000000000000" \
        "000000000000000000000000"
      ].pack('H*')
    end

    specify do
      expect(packet.struct_size).to eq(17)
    end

    specify do
      expect(packet.data_length).to eq(92)
    end

    specify do
      expect(packet.data.length).to eq(92)
    end

    specify do
      expect(packet.data.length).to eq(packet.data_length)
    end

    specify do
      expect(packet.data_offset).to eq(0x0050)
    end

    specify 'data' do
      expect(packet.data).to eq([
        "05000c03100000005c00000002000000b810b8104a1e00000d005c504950455c" \
        "73727673766300000200000000000000045d888aeb1cc9119fe808002b104860" \
        "02000000030003000000000000000000000000000000000000000000"
      ].pack("H*"))
    end

    specify do
      expect(packet.data_remaining).to eq(0)
    end

    specify do
      expect(packet.reserved2).to eq(0)
    end

  end


end
