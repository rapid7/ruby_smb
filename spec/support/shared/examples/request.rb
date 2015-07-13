require 'spec_helper'

RSpec.shared_examples "request" do |command|
  context 'header' do
    specify do
      expect(packet.header.magic).to eq("\xfeSMB".force_encoding("binary"))
    end

    specify do
      if packet.header.has_flag?(:SIGNING)
        # TODO actually check the signature
        expect(packet.header.signature).not_to eq(("\x00" * 16).force_encoding("binary"))
      else
        expect(packet.header.signature).to eq(("\x00" * 16).force_encoding("binary"))
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
