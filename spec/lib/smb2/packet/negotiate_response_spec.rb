require 'smb2'

RSpec.describe Smb2::Packet::NegotiateResponse do
  subject(:packet) do
    described_class.new(data)
  end

  context 'with packet bytes' do
    let(:data) do
      [
        "fe534d4240000100000000000000010001000000000000000000000000000000" \
        "fffe000000000000000000000000000000000000000000000000000000000000" \
        "41000100100200007daab8d583aa1e49b86c7888fd7671900700000000001000" \
        "000010000000100047729403eb0dd001ff33b7b3900dd00180002a0000000000" \
        "602806062b0601050502a01e301ca01a3018060a2b06010401823702021e060a" \
        "2b06010401823702020a"
      ].pack('H*')
    end

    context 'header' do
      specify do
        expect(packet.header.magic).to eq("\xfeSMB".force_encoding("binary"))
      end
      specify do
        expect(packet.header.signature).to eq(("\x00"*16).force_encoding("binary"))
      end
      specify do
        expect(packet.header.command).to eq(Smb2::Commands::NEGOTIATE)
      end
    end

    context 'body' do
      specify do
        expect(packet.struct_size).to eq(65)
      end
    end

  end

end


