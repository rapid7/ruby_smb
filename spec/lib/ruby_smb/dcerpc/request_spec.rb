require 'spec_helper'

RSpec.describe RubySMB::Dcerpc::Request do

  let(:request){ described_class.new(
      opnum: 15,
       stub: RubySMB::Dcerpc::Srvsvc::NetShareEnumAll.new(host: '192.161.204.122').to_binary_s
      )
  }

  it 'should create a Request PDU' do
    expect(request.do_num_bytes).to eq 104
  end
end