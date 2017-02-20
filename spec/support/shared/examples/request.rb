RSpec.shared_examples 'request' do |command|
  context 'header' do
    specify do
      expect(packet.magic).to eq("\xfeSMB".force_encoding('binary'))
    end

    specify do
      if packet.has_header_flag?(:SIGNING)
        # TODO: actually check the signature
        expect(packet.signature).not_to eq(("\x00" * 16).force_encoding('binary'))
      else
        expect(packet.signature).to eq(("\x00" * 16).force_encoding('binary'))
      end
    end

    specify do
      expect(packet.command).to eq(command)
    end

    it { is_expected.not_to have_header_flag(:RESPONSE) }
    it { is_expected.to respond_to(:channel_seq) }
    it { is_expected.to respond_to(:channel_seq=) }
    it { is_expected.to respond_to(:header_reserved) }
    it { is_expected.to respond_to(:header_reserved=) }
  end
end
