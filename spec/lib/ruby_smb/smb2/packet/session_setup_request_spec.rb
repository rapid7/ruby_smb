require 'ruby_smb/smb2'
require 'net/ntlm'
require 'support/shared/examples/request'

RSpec.describe RubySMB::Smb2::Packet::SessionSetupRequest do
  subject(:packet) do
    described_class.new(data)
  end

  context 'with NTLMSSP Type1 blob' do
    let(:data) do
      [
        "fe534d42400001000000000001001f0000000000000000000100000000000000" \
        "fffe000000000000000000000000000000000000000000000000000000000000" \
        "19000001010000000000000058004a001500000000040000604806062b060105" \
        "0502a03e303ca00e300c060a2b06010401823702020aa22a04284e544c4d5353" \
        "500001000000978208e2000000000000000000000000000000000602f0230000" \
        "000f"
      ].pack('H*')
    end

    it_behaves_like "packet"
    it_behaves_like "request", RubySMB::Smb2::COMMANDS[:SESSION_SETUP]

    specify 'body' do
      expect(packet.struct_size).to eq(25)
      expect(packet.flags).to eq(0)
      expect(packet.security_mode).to eq(1)
      expect(packet.channel).to eq(0)
      expect(packet.capabilities).to eq(1)
      expect(packet.previous_session_id).to eq(0x0000_0400_0000_0015)
      expect(packet.security_blob_length).to eq(74)
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
        expect { Net::NTLM::Message.parse(ntlmssp_data) }.not_to raise_error
        expect(Net::NTLM::Message.parse(ntlmssp_data)).to be_a(Net::NTLM::Message::Type1)
      end
    end

  end

  context 'with NTLMSSP Type3 blob' do
    let(:data) do
      [
        "fe534d4240000100000000000100010000000000000000000200000000000000" \
        "fffe000000000000190000000004000000000000000000000000000000000000" \
        "190000010100000000000000580035021500000000040000a18202313082022d" \
        "a0030a0101a28202100482020c4e544c4d5353500003000000180018009c0000" \
        "0048014801b40000000c000c00580000001a001a00640000001e001e007e0000" \
        "0010001000fc010000158288e20602f0230000000f25bb5008dc2ffa313d8ef3" \
        "3408465f0b570069006e00380033003200610064006d0069006e006900730074" \
        "007200610074006f007200570049004e002d0056005600460037004b00470055" \
        "004b005500480043000000000000000000000000000000000000000000000000" \
        "003f1e4a5ed999c09744eeb6f8538513260101000000000000a7d39603eb0dd0" \
        "010b1dbc978d02a2b10000000002001e00570049004e002d00420035004a004e" \
        "00330052004800470046003300310001001e00570049004e002d00420035004a" \
        "004e00330052004800470046003300310004001e00570049004e002d00420035" \
        "004a004e00330052004800470046003300310003001e00570049004e002d0042" \
        "0035004a004e00330052004800470046003300310007000800a7d39603eb0dd0" \
        "01060004000200000008003000300000000000000001000000002000004956bb" \
        "4033960496bb15b2ebd2e0f25e992194fcb42743a87ba38d35549cb0670a0010" \
        "00000000000000000000000000000000000900280063006900660073002f0031" \
        "00390032002e003100360038002e003100300030002e00310034003000000000" \
        "00000000000000000058f00941bcb767e7550260646782b705a3120410010000" \
        "0060c61445d947bec400000000"
      ].pack('H*')
    end

    specify 'header' do
      expect(packet.magic).to eq("\xfeSMB".force_encoding("binary"))
      expect(packet.signature).to eq(("\x00" * 16).force_encoding("binary"))
      expect(packet.command).to eq(RubySMB::Smb2::COMMANDS[:SESSION_SETUP])
    end

    specify 'body' do
      expect(packet.struct_size).to eq(25)
      expect(packet.flags).to eq(0)
      expect(packet.security_mode).to eq(1)
      expect(packet.channel).to eq(0)
      expect(packet.capabilities).to eq(1)
      expect(packet.previous_session_id).to eq(0x0000_0400_0000_0015)
      expect(packet.security_blob_length).to eq(565)
    end

    context 'blob data' do
      subject(:gssapi_data) do
        described_class.new(data).security_blob
      end
      let(:ntlmssp_data) do
        gssapi_data[gssapi_data.index("NTLMSSP")..-1]
      end

      specify do
        expect { Net::NTLM::Message.parse(ntlmssp_data) }.not_to raise_error
        expect(Net::NTLM::Message.parse(ntlmssp_data)).to be_a(Net::NTLM::Message::Type3)
      end
    end

    describe '#has_flag?' do
      specify do
        expect { packet.has_flag?(:garbage) }.to raise_error(RubySMB::Smb2::Packet::InvalidFlagError)
      end
      specify do
        expect(packet.has_flag?(:SESSION_BINDING_REQUEST)).to be_falsey
      end
    end

  end
end
