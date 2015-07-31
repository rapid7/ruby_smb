RSpec.describe RubySMB::SMB2::Packet::NegotiateRequest do
  subject(:packet) do
    described_class.new(data)
  end

  context 'with packet bytes' do
    let(:client_guid) { "ec1cb173f176e411af9e000c293f25dc" }
    let(:dialects) { "020210020003" }
    let(:data) do
      [
        "fe534d42400001000000000000001f0000000000000000000000000000000000" \
        "fffe000000000000000000000000000000000000000000000000000000000000" \
        "24000300010000007f000000#{client_guid}00000000" \
        "00000000#{dialects}"

      ].pack('H*')
    end

    it_behaves_like 'packet'
    it_behaves_like 'request', RubySMB::SMB2::COMMANDS[:NEGOTIATE]
    it_behaves_like 'smb2_negotiate_packet_header'

    context 'packet body element hardcoded values' do
      it 'packet.struct_size should equal 36' do
        expect(packet.struct_size).to eq(36)
      end

      it 'packet.dialect_count should equal 3' do
        expect(packet.dialect_count).to eq(3)
      end

      it 'packet.security_mode should equal 1' do
        expect(packet.security_mode).to eq(1)
      end

      it 'packet.reserved should equal 0' do
        expect(packet.reserved).to eq(0)
      end

      it 'packet.capabilities should equal 127' do
        # TODO constantize
        expect(packet.capabilities).to eq(127)
      end

      it 'packet.client_guid should equal the specified value' do
        expect(packet.client_guid).to eq([client_guid].pack("H*"))
      end

      it 'packet.dialects should equal the specified value' do
        expect(packet.dialects).to eq([dialects].pack("H*"))
      end

    end
  end
end
