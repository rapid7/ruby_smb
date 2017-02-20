RSpec.shared_examples 'smb2_negotiate_packet_header' do
  it 'should use the known "magic" string' do
    expect(packet.magic).to eq("\xfeSMB".force_encoding('binary'))
  end

  it 'should contain the null byte signature' do
    expect(packet.signature).to eq(("\x00" * 16).force_encoding('binary'))
  end

  it 'should have the NEGOTIATE command in the packet\'s command section' do
    expect(packet.command).to eq(RubySMB::SMB2::COMMANDS[:NEGOTIATE])
  end
end
