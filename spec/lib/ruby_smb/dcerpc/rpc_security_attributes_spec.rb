RSpec.describe RubySMB::Dcerpc::RpcSecurityDescriptor do
  subject(:packet) { described_class.new }

  it { is_expected.to respond_to :lp_security_descriptor }
  it { is_expected.to respond_to :cb_in_security_descriptor }
  it { is_expected.to respond_to :cb_out_security_descriptor }

  it 'is little endian' do
    expect(described_class.fields.instance_variable_get(:@hints)[:endian]).to eq :little
  end

  describe '#lp_security_descriptor' do
    it 'should be a NdrLpByteArray structure' do
      expect(packet.lp_security_descriptor).to be_a RubySMB::Dcerpc::Ndr::NdrLpByteArray
    end
  end

  describe '#cb_in_security_descriptor' do
    it 'should be a 32-bit unsigned integer' do
      expect(packet.cb_in_security_descriptor).to be_a BinData::Uint32le
    end
  end

  describe '#cb_out_security_descriptor' do
    it 'should be a 32-bit unsigned integer' do
      expect(packet.cb_out_security_descriptor).to be_a BinData::Uint32le
    end
  end

  describe '#read' do
    context 'with a null pointer' do
      it 'reads its own binary representation' do
        raw = packet.to_binary_s
        expect(described_class.read(raw)).to eq(packet)
        expect(described_class.read(raw).to_binary_s).to eq(raw)
      end
    end

    context 'with a normal RpcSecurityAttributes structure' do
      it 'reads its own binary representation' do
        packet.lp_security_descriptor = RubySMB::Dcerpc::Ndr::NdrLpByteArray.new([1, 2, 3])
        packet.cb_in_security_descriptor = 90
        packet.cb_out_security_descriptor = 33
        raw = packet.to_binary_s
        expect(described_class.read(raw)).to eq(packet)
        expect(described_class.read(raw).to_binary_s).to eq(raw)
      end
    end
  end
end

RSpec.describe RubySMB::Dcerpc::RpcSecurityAttributes do
  subject(:packet) { described_class.new }

  it { is_expected.to respond_to :n_length }
  it { is_expected.to respond_to :rpc_security_descriptor }
  it { is_expected.to respond_to :b_inheritHandle }

  it 'is little endian' do
    expect(described_class.fields.instance_variable_get(:@hints)[:endian]).to eq :little
  end

  describe '#n_length' do
    it 'should be a 32-bit unsigned integer' do
      expect(packet.n_length).to be_a BinData::Uint32le
    end
  end

  describe '#rpc_security_descriptor' do
    it 'should be a RpcSecurityDescriptor structure' do
      expect(packet.rpc_security_descriptor).to be_a RubySMB::Dcerpc::RpcSecurityDescriptor
    end
  end

  describe '#b_inheritHandle' do
    it 'should be a 8-bit unsigned integer' do
      expect(packet.b_inheritHandle).to be_a BinData::Uint8
    end
  end

  describe '#read' do
    context 'with a null pointer' do
      it 'reads its own binary representation' do
        raw = packet.to_binary_s
        expect(described_class.read(raw)).to eq(packet)
        expect(described_class.read(raw).to_binary_s).to eq(raw)
      end
    end

    context 'with a normal RpcSecurityAttributes structure' do
      it 'reads its own binary representation' do
        packet.n_length = 3
        packet.rpc_security_descriptor = RubySMB::Dcerpc::RpcSecurityDescriptor.new
        packet.rpc_security_descriptor.lp_security_descriptor = [1, 2, 3]
        packet.rpc_security_descriptor.cb_in_security_descriptor = 33
        packet.rpc_security_descriptor.cb_out_security_descriptor = 22
        packet.b_inheritHandle = 90
        raw = packet.to_binary_s
        expect(described_class.read(raw)).to eq(packet)
        expect(described_class.read(raw).to_binary_s).to eq(raw)
      end
    end
  end
end

RSpec.describe RubySMB::Dcerpc::PrpcSecurityAttributes do
  it 'is NdrPointer subclass' do
    expect(described_class).to be < RubySMB::Dcerpc::Ndr::NdrPointer
  end

  subject(:packet) { described_class.new }

  it { is_expected.to respond_to :referent }

  it 'is little endian' do
    expect(described_class.fields.instance_variable_get(:@hints)[:endian]).to eq :little
  end

  describe '#referent' do
    it 'should be a RpcSecurityAttributes structure' do
      expect(packet.referent).to be_a RubySMB::Dcerpc::RpcSecurityAttributes
    end

    it 'exists if superclass #referent_id is not zero' do
      packet.referent_id = 0xCCCC
      expect(packet.referent?).to be true
    end

    it 'does not exist if superclass #referent_id is zero' do
      packet.referent_id = 0
      expect(packet.referent?).to be false
    end
  end

  describe '#read' do
    context 'with a null pointer' do
      it 'reads its own binary representation' do
        raw = packet.to_binary_s
        expect(described_class.read(raw)).to eq(packet)
        expect(described_class.read(raw).to_binary_s).to eq(raw)
      end
    end

    context 'with a normal RpcSecurityAttributes structure' do
      it 'reads its own binary representation' do
        struct = RubySMB::Dcerpc::RpcSecurityAttributes.new
        struct.n_length = 5
        struct.rpc_security_descriptor = RubySMB::Dcerpc::RpcSecurityDescriptor.new
        struct.rpc_security_descriptor.lp_security_descriptor = [1, 2, 3]
        struct.rpc_security_descriptor.cb_in_security_descriptor = 33
        struct.rpc_security_descriptor.cb_out_security_descriptor = 22
        struct.b_inheritHandle = 4
        packet.set(struct)
        raw = packet.to_binary_s
        expect(described_class.read(raw)).to eq(packet)
        expect(described_class.read(raw).to_binary_s).to eq(raw)
      end
    end
  end
end

