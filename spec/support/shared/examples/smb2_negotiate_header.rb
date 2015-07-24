require 'spec_helper'

RSpec.shared_examples 'smb2_negotiate_packet_header' do
  specify do
    expect(packet.magic).to eq("\xfeSMB".force_encoding("binary"))
  end
  specify do
    expect(packet.signature).to eq(("\x00" * 16).force_encoding("binary"))
  end
  specify do
    expect(packet.command).to eq(RubySMB::Smb2::COMMANDS[:NEGOTIATE])
  end
end