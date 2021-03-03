RSpec.describe RubySMB::Dcerpc::Winreg::RpcHkey do
  subject(:packet) { described_class.new }

  it 'is NdrContextHandle subclass' do
    expect(described_class).to be < RubySMB::Dcerpc::Ndr::NdrContextHandle
  end
end

RSpec.describe RubySMB::Dcerpc::Winreg::CreateKeyRequest do
  subject(:packet) { described_class.new }


  it 'is little endian' do
    expect(described_class.fields.instance_variable_get(:@hints)[:endian]).to eq :little
  end

  it { is_expected.to respond_to :hkey }
  it { is_expected.to respond_to :lp_sub_key }
  it { is_expected.to respond_to :pad1 }
  it { is_expected.to respond_to :lp_class }
  it { is_expected.to respond_to :pad2 }
  it { is_expected.to respond_to :dw_options }
  it { is_expected.to respond_to :sam_desired }
  it { is_expected.to respond_to :lp_security_attributes }
  it { is_expected.to respond_to :pad3 }
  it { is_expected.to respond_to :lpdw_disposition }

  describe '#hkey' do
    it 'is a RpcHkey structure' do
      expect(packet.hkey).to be_a RubySMB::Dcerpc::Winreg::RpcHkey
    end
  end

  describe '#lp_sub_key' do
    it 'is a RrpUnicodeString structure' do
      expect(packet.lp_sub_key).to be_a RubySMB::Dcerpc::RrpUnicodeString
    end
  end

  describe '#pad1' do
    it 'is a string' do
      expect(packet.pad1).to be_a BinData::String
    end

    it 'should keep #lp_class 4-byte aligned' do
      packet.lp_sub_key = "test"
      expect(packet.lp_class.abs_offset % 4).to eq 0
    end
  end

  describe '#lp_class' do
    it 'is a RrpUnicodeString structure' do
      expect(packet.lp_class).to be_a RubySMB::Dcerpc::RrpUnicodeString
    end
  end

  describe '#pad2' do
    it 'is a string' do
      expect(packet.pad1).to be_a BinData::String
    end

    it 'should keep #dw_options 4-byte aligned' do
      packet.lp_class = "test"
      expect(packet.dw_options.abs_offset % 4).to eq 0
    end
  end

  describe '#dw_options' do
    it 'is a 32-bit unsigned integer' do
      expect(packet.dw_options).to be_a BinData::Uint32le
    end
  end

  describe '#sam_desired' do
    it 'is a Regsam structure' do
      expect(packet.sam_desired).to be_a RubySMB::Dcerpc::Winreg::Regsam
    end
  end

  describe '#lp_security_attributes' do
    it 'is a PrpcSecurityAttributes structure' do
      expect(packet.lp_security_attributes).to be_a RubySMB::Dcerpc::PrpcSecurityAttributes
    end
  end

  describe '#pad3' do
    it 'is a string' do
      expect(packet.pad1).to be_a BinData::String
    end

    it 'should keep #lpdw_disposition 4-byte aligned' do
      sc = RubySMB::Dcerpc::RpcSecurityDescriptor.new(lp_security_descriptor: [1,2,3,4])
      packet.lp_security_attributes = RubySMB::Dcerpc::RpcSecurityAttributes.new(rpc_security_descriptor: sc)
      expect(packet.lpdw_disposition.abs_offset % 4).to eq 0
    end
  end

  describe '#lpdw_disposition' do
    it 'is a Uint32Ptr structure' do
      expect(packet.lpdw_disposition).to be_a RubySMB::Dcerpc::Ndr::Uint32Ptr
    end
  end

  describe '#initialize_instance' do
   it 'sets #opnum to REG_CREATE_KEY constant' do
      expect(packet.opnum).to eq(RubySMB::Dcerpc::Winreg::REG_CREATE_KEY)
    end
  end
end

