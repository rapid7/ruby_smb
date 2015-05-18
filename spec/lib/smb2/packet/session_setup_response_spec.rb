require 'smb2'
require 'net/ntlm'

RSpec.describe Smb2::Packet::SessionSetupResponse do
  subject(:packet) do
    described_class.new(data)
  end

  context 'with NTLMSSP Type2 blob' do
    let(:data) do
      [
        "fe534d4240000100160000c001001f0001000000000000000100000000000000" \
        "fffe000000000000190000000004000000000000000000000000000000000000" \
        "0900000048000f01a182010b30820107a0030a0101a10c060a2b060104018237" \
        "02020aa281f10481ee4e544c4d53535000020000001e001e003800000015828a" \
        "e251440167941b1aaa000000000000000098009800560000000601b11d000000" \
        "0f570049004e002d00420035004a004e00330052004800470046003300310002" \
        "001e00570049004e002d00420035004a004e0033005200480047004600330031" \
        "0001001e00570049004e002d00420035004a004e003300520048004700460033" \
        "00310004001e00570049004e002d00420035004a004e00330052004800470046" \
        "003300310003001e00570049004e002d00420035004a004e0033005200480047" \
        "0046003300310007000800a7d39603eb0dd00100000000"
      ].pack('H*')
    end

    specify 'header' do
      expect(packet.header.magic).to eq("\xfeSMB".force_encoding("binary"))
      expect(packet.header.signature).to eq(("\x00"*16).force_encoding("binary"))
      expect(packet.header.command).to eq(Smb2::COMMANDS[:SESSION_SETUP])

    end

    context 'blob data' do
      subject(:gssapi_data) do
        described_class.new(data).security_blob
      end
      let(:ntlmssp_data) do
        # TODO parse
        gssapi_data[gssapi_data.index("NTLMSSP")..-1]
      end

      specify do
        expect{ Net::NTLM::Message.parse(ntlmssp_data) }.not_to raise_error
        parsed = Net::NTLM::Message.parse(ntlmssp_data)
        expect(parsed).to be_a(Net::NTLM::Message::Type2)
        expect(parsed.flag).to eq(0xe28a8215)
      end
    end

    describe '#to_s' do
      specify do
        expect(packet.to_s).to eq(data)
      end
    end

  end
end
