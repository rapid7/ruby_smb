require 'smb2'

RSpec.describe Smb2::Packet::TreeConnectResponse do
  subject(:packet) do
    described_class.new(data)
  end

  context 'data' do
    let(:data) do
      [
        "fe534d4240000100000000000300010001000000000000000300000000000000" \
        "fffe000001000000190000000004000000000000000000000000000000000000" \
        "100002003000000000000000ff011f01"
      ].pack('H*')
    end

    specify 'header' do
      expect(packet.header.magic).to eq("\xfeSMB".force_encoding("binary"))
      expect(packet.header.signature).to eq(("\x00"*16).force_encoding("binary"))
      expect(packet.header.command).to eq(Smb2::Commands::TREE_CONNECT)
      expect(packet.header).to have_flag(:RESPONSE)
    end

    specify 'body' do
      expect(packet.struct_size).to eq(16)
      # 0x02 => Named pipe
      # @todo Constantize
      expect(packet.share_type).to eq(0x02)
      # No idea what this 0x30 means. Wireshark leaves these bits blank
      expect(packet.share_flags).to eq(0x30)
      expect(packet.share_capabilities).to eq(0)
      # @todo Constantize these flags
      expect(packet.access_mask).to eq(0x011f01ff)
    end

  end

end


