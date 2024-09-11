RSpec.describe RubySMB::Dcerpc::Wkssvc::NetrWkstaUserEnumRequest do
  subject(:packet) { described_class.new }

  def random_str(nb = 8)
    nb.times.map { rand('a'.ord..'z'.ord).chr }.join
  end

  it { is_expected.to respond_to :server_name }
  it { is_expected.to respond_to :user_info }
  it { is_expected.to respond_to :preferred_max_length }
  it { is_expected.to respond_to :result_handle }
  it { is_expected.to respond_to :opnum }

  it 'is little endian' do
    expect(described_class.fields.instance_variable_get(:@hints)[:endian]).to eq :little
  end
  it 'is a BinData::Record' do
    expect(packet).to be_a(BinData::Record)
  end
  describe '#server_name' do
    it 'is a WkssvcIdentifyHandle structure' do
      expect(packet.server_name).to be_a RubySMB::Dcerpc::Wkssvc::WkssvcIdentifyHandle
    end
  end
  describe '#user_info' do
    it 'is a WkstaUserEnumStructure structure' do
      expect(packet.user_info).to be_a RubySMB::Dcerpc::Wkssvc::WkstaUserEnumStructure
    end
  end
  describe '#preferred_max_length' do
    it 'is a NdrUint32 structure' do
      expect(packet.preferred_max_length).to be_a RubySMB::Dcerpc::Ndr::NdrUint32
    end

    it 'has a default value of 0xFFFFFFFF' do
      expect(packet.preferred_max_length).to eq(0xFFFFFFFF)
    end
  end
  describe '#result_handle' do
    it 'is a NdrUint32Ptr structure' do
      expect(packet.result_handle).to be_a RubySMB::Dcerpc::Ndr::NdrUint32Ptr
    end

    it 'has a default value of 0' do
      expect(packet.result_handle).to eq(0)
    end
  end
  describe '#initialize_instance' do
    it 'sets #opnum to NETR_WKSTA_USER_ENUM constant' do
      expect(packet.opnum).to eq(RubySMB::Dcerpc::Wkssvc::NETR_WKSTA_USER_ENUM)
    end
  end
  it 'reads itself' do
    packet = described_class.new(
      server_name: 'TestServer',
      user_info: {
        level: RubySMB::Dcerpc::Wkssvc::WKSTA_USER_INFO_0,
        info: {
          wkui0_entries_read: 1,
          wkui0_buffer: [{
            wkui0_username: random_str
          }],
        },
      },
      preferred_max_length: 0xFFFFFFFF,
      result_handle: 0
    )
    binary = packet.to_binary_s
    expect(described_class.read(binary)).to eq(packet)
  end
end
