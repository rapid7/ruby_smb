
RSpec.shared_examples "request" do |command|
  context 'header' do
    specify do
      expect(packet.header.magic).to eq("\xfeSMB".b)
    end
    specify do
      expect(packet.header.signature).to eq(("\x00"*16).b)
    end
    specify do
      expect(packet.header.command).to eq(command)
    end
    specify do
      expect(packet.header).not_to have_flag(:RESPONSE)
    end
  end
end

