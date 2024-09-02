RSpec.describe RubySMB::Dcerpc::Wkssvc::WkssvcIdentifyHandle do
  subject(:packet) { described_class.new }

  it 'is a Ndr::NdrWideStringPtr' do
    expect(packet).to be_a(RubySMB::Dcerpc::Ndr::NdrWideStringPtr)
  end
end
