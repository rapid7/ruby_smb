RSpec.shared_examples "request" do |command|
  context 'header' do
    specify do
      expect(packet.header.magic).to eq("\xfeSMB".b)
    end

    specify do
      if packet.header.has_flag?(:SIGNING)
        # TODO actually check the signature
        expect(packet.header.signature).not_to eq(("\x00"*16).b)
      else
        expect(packet.header.signature).to eq(("\x00"*16).b)
      end
    end

    specify do
      expect(packet.header.command).to eq(command)
    end

    specify do
      expect(packet.header).not_to have_flag(:RESPONSE)
    end
  end
end

