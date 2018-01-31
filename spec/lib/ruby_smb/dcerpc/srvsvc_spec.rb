require 'spec_helper'

RSpec.describe RubySMB::Dcerpc::Srvsvc do

  describe 'when making a NetShareEnumAll struct' do
    let(:stub){ RubySMB::Dcerpc::Srvsvc::NetShareEnumAll.new(server_name: '192.161.204.122') }

    it 'crafts an 8 octet aligned stub' do
      expect(stub.do_num_bytes).to eq 80
    end
  end

end
