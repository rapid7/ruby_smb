RSpec.describe RubySMB::Dcerpc::Svcctl::OpenServiceWRequest do
  subject(:packet) { described_class.new }

  it { is_expected.to respond_to :lp_sc_handle }
  it { is_expected.to respond_to :lp_service_name }
  it { is_expected.to respond_to :pad }
  it { is_expected.to respond_to :dw_desired_access }

  it 'is little endian' do
    expect(described_class.fields.instance_variable_get(:@hints)[:endian]).to eq :little
  end


  describe '#lp_sc_handle' do
    it 'is a ScRpcHandle structure' do
      expect(packet.lp_sc_handle).to be_a RubySMB::Dcerpc::Svcctl::ScRpcHandle
    end
  end

  describe '#lp_service_name' do
    it 'is a ConfVarWideString structure' do
      expect(packet.lp_service_name).to be_a RubySMB::Dcerpc::Ndr::ConfVarWideString
    end
  end

  describe '#pad' do
    it 'is a string' do
      expect(packet.pad).to be_a BinData::String
    end

    it 'should keep #dw_desired_access 4-byte aligned' do
      packet.lp_service_name = "test"
      expect(packet.dw_desired_access.abs_offset % 4).to eq 0
    end
  end

  describe '#dw_desired_access' do
    it 'is a 32-bit unsigned integer' do
      expect(packet.dw_desired_access).to be_a BinData::Uint32le
    end
  end

  describe '#initialize_instance' do
    it 'sets #opnum to OPEN_SERVICE_W constant' do
      expect(packet.opnum).to eq(RubySMB::Dcerpc::Svcctl::OPEN_SERVICE_W)
    end
  end

  it 'reads its own binary representation and outputs the same packet' do
    packet = described_class.new(
      lp_sc_handle: {context_handle_attributes: 0, context_handle_uuid: '367abb81-9844-35f1-ad32-98f038001003'},
      lp_service_name: 'test',
      dw_desired_access: 3
    )
    binary = packet.to_binary_s
    expect(described_class.read(binary)).to eq(packet)
  end
end

