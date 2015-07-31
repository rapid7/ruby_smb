RSpec.shared_examples 'write_response_channel_info' do

  it 'should conform to the expected offset' do
    expect(packet.channel_info_offset).to eq(0)
  end

  it 'should conform to the expected length' do
    expect(packet.channel_info_length).to eq(0)
  end

  it 'should be empty' do
    expect(packet.channel_info).to eq('')
  end
end
