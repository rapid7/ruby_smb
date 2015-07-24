require 'spec_helper'

RSpec.shared_examples "write_response_channel_info" do

  specify do
    expect(packet.channel_info_offset).to eq(0)
    expect(packet.channel_info_length).to eq(0)
    expect(packet.channel_info).to eq('')
  end

end
