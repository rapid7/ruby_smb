require 'ruby_smb/smb2'

RSpec.describe RubySMB::Smb2::Packet::TreeConnectResponse do
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

    it_behaves_like "packet"

    specify 'header' do
      expect(packet.magic).to eq("\xfeSMB".force_encoding("binary"))
      expect(packet.signature).to eq(("\x00" * 16).force_encoding("binary"))
      expect(packet.command).to eq(RubySMB::Smb2::COMMANDS[:TREE_CONNECT])
      expect(packet).to have_header_flag(:RESPONSE)
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
