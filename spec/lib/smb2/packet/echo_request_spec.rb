require 'spec_helper'

RSpec.describe Smb2::Packet::EchoRequest do

  subject(:echo_request_packet){ described_class.new }

  context "COMMAND" do
    it 'should be :ECHO' do
      expect(described_class.const_get("COMMAND")).to eq :ECHO
    end
  end

  context "structure_size" do
    it 'should be a 16-bit field per the SMB spec' do
      structure_size_field = echo_request_packet.fields.detect{|f| f.display_name == :structure_size }
      expect(structure_size_field.length).to eq 16
    end


    it "should be hardcoded to 4 bits per the SMB spec" do
      expect(echo_request_packet.structure_size).to eq 4
    end
  end

  context "reserved" do
    it 'should be a 16-bit field per the SMB spec' do
      reserved_field = echo_request_packet.fields.detect{|f| f.display_name == :reserved }
      expect(reserved_field.length).to eq 16
    end
  end

end
