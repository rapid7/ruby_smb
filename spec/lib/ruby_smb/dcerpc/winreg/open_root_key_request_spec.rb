RSpec.describe RubySMB::Dcerpc::Winreg::PRegistryServerName do
  it 'is Ndr::FixArray subclass' do
    expect(described_class).to be < RubySMB::Dcerpc::Ndr::FixArray
  end

  subject(:packet) { described_class.new }

  it { is_expected.to respond_to :ref_id }

  it 'is an array of UTF-16LE strings' do
    expect(packet[0]).to be_a RubySMB::Field::String16
  end

  it 'is :null if #ref_id is 0' do
    packet.ref_id = 0
    expect(packet).to eq(:null)
  end

  it 'is always 2 wide-characters long' do
    expect(packet.size).to eq(2)
  end

  #it 'reads 4-bytes' do
  #  str = 'spec_test'.encode('utf-16le')
  #  packet.referent.read(str)
  #  expect(packet.referent.to_binary_s.bytes).to eq(str.bytes[0,4])
  #end
end

RSpec.describe RubySMB::Dcerpc::Winreg::OpenRootKeyRequest do
  subject(:packet) { described_class.new }

  it { is_expected.to respond_to :p_registry_server_name }
  it { is_expected.to respond_to :sam_desired }
  it { is_expected.to respond_to :opnum }

  it 'is little endian' do
    expect(described_class.fields.instance_variable_get(:@hints)[:endian]).to eq :little
  end

  describe '#p_registry_server_name' do
    it 'is a PRegistryServerName structure' do
      expect(packet.p_registry_server_name).to be_a RubySMB::Dcerpc::Winreg::PRegistryServerName
    end
  end

  describe '#sam_desired' do
    it 'is a Regsam structure' do
      expect(packet.sam_desired).to be_a RubySMB::Dcerpc::Winreg::Regsam
    end
  end

  describe '#initialize_instance' do
    context 'when an #opnum parameter is provided' do
      it 'sets #opnum to the parameter\'s value' do
        packet = described_class.new(opnum: RubySMB::Dcerpc::Winreg::OPEN_HKLM)
        expect(packet.opnum).to eq(RubySMB::Dcerpc::Winreg::OPEN_HKLM)
      end
    end

    it 'sets #p_registry_server_name.referent to :null' do
      expect(packet.p_registry_server_name).to eq(:null)
    end

    context 'when #opnum is not OPEN_HKPD, OPEN_HKPT or OPEN_HKPN' do
      it 'sets the #sam_desired.maximum flag' do
        packet = described_class.new(opnum: RubySMB::Dcerpc::Winreg::OPEN_HKCR)
        expect(packet.sam_desired.maximum).to eq(1)
      end
    end

    context 'when #opnum is OPEN_HKPD' do
      it 'does not set the #sam_desired.maximum flag' do
        packet = described_class.new(opnum: RubySMB::Dcerpc::Winreg::OPEN_HKPD)
        expect(packet.sam_desired.maximum).to eq(0)
      end
    end

    context 'when #opnum is OPEN_HKPT' do
      it 'does not set the #sam_desired.maximum flag' do
        packet = described_class.new(opnum: RubySMB::Dcerpc::Winreg::OPEN_HKPT)
        expect(packet.sam_desired.maximum).to eq(0)
      end
    end

    context 'when #opnum is OPEN_HKPN' do
      it 'does not set the #sam_desired.maximum flag' do
        packet = described_class.new(opnum: RubySMB::Dcerpc::Winreg::OPEN_HKPN)
        expect(packet.sam_desired.maximum).to eq(0)
      end
    end
  end
end
