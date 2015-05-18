require 'smb2'

RSpec.describe Smb2::Packet::RequestHeader do
  let(:data) { nil }
  subject(:packet) do
    described_class.new(data)
  end

  specify 'has accessors for all protocol fields' do
    expect(packet).to respond_to(:magic)
    expect(packet).to respond_to(:header_len)
    expect(packet).to respond_to(:credit_charge)
    expect(packet).to respond_to(:channel_seq)
    expect(packet).to respond_to(:reserved)
    expect(packet).to respond_to(:command)
    expect(packet).to respond_to(:credits_requested)
    expect(packet).to respond_to(:flags)
    expect(packet).to respond_to(:chain_offset)
    expect(packet).to respond_to(:command_seq)
    expect(packet).to respond_to(:process_id)
    expect(packet).to respond_to(:tree_id)
    expect(packet).to respond_to(:session_id)
    expect(packet).to respond_to(:signature)
  end

  context 'with a SessionSetupRequest' do
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

    specify do
      expect(packet.magic).to eq("\xfeSMB".force_encoding("binary"))
      expect(packet.header_len).to eq(64)
      expect(packet.credit_charge).to eq(1)
      expect(packet.command).to eq(Smb2::COMMANDS[:SESSION_SETUP])
      expect(packet.credits_requested).to eq(31)
      expect(packet.signature).to eq(("\x00" * 16).force_encoding("binary"))
    end

    describe '#has_flag?' do
      specify do
        expect { packet.has_flag?(:garbage) }.to raise_error(Smb2::Packet::InvalidFlagError)
      end
      specify do
        expect(packet.has_flag?(:RESPONSE)).to be_falsey
      end
      specify do
        expect(packet.has_flag?(:ASYNC)).to be_falsey
      end
    end

    describe '#to_s' do
      specify do
        expect(packet.to_s).to eq(data)
      end
    end

  end

end
