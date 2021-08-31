RSpec.describe RubySMB::Dcerpc::RrpUnicodeString do
  subject(:packet) { described_class.new }

  it { is_expected.to respond_to :buffer_length }
  it { is_expected.to respond_to :maximum_length }
  it { is_expected.to respond_to :buffer }

  it 'is little endian' do
    expect(described_class.fields.instance_variable_get(:@hints)[:endian]).to eq :little
  end

  it 'has :byte_align parameter set to the expected value' do
    expect(described_class.default_parameters[:byte_align]).to eq(4)
  end

  describe '#buffer_length' do
    it 'should be a NdrUint16' do
      expect(packet.buffer_length).to be_a RubySMB::Dcerpc::Ndr::NdrUint16
    end
    it 'is 0 by default' do
      expect(packet.buffer_length).to eq(0)
    end
  end

  describe '#maximum_length' do
    it 'should be a NdrUint16' do
      expect(packet.maximum_length).to be_a RubySMB::Dcerpc::Ndr::NdrUint16
    end
    it 'is 0 by default' do
      expect(packet.maximum_length).to eq(0)
    end
  end

  describe '#buffer' do
    it 'should be a NdrWideStringzPtr' do
      expect(packet.buffer).to be_a RubySMB::Dcerpc::Ndr::NdrWideStringzPtr
    end
    it 'is :null by default' do
      expect(packet.buffer).to eq(:null)
    end
  end

  describe '#assign' do
    context 'with a string' do
      before :example do
        packet.assign('spec_test')
      end

      [BinData::Stringz, BinData::String, String].each do |klass|
        context "with a #{klass}" do
          it 'sets #buffer to the expected value' do
            expect(packet.buffer).to eq(RubySMB::Dcerpc::Ndr::NdrWideStringPtr.new(klass.new('spec_test')))
          end

          it 'sets #buffer_length to the expected value' do
            expect(packet.buffer_length).to eq(('spec_test'.size + 1) * 2)
          end

          it 'sets #maximum_length to the expected value' do
            expect(packet.maximum_length).to eq(('spec_test'.size + 1) * 2)
          end
        end
      end
    end

    context 'with a :null pointer' do
      before :example do
        packet.assign(:null)
      end
      it 'sets #buffer to :null' do
        expect(packet.buffer).to eq(:null)
      end

      it 'sets #buffer_length to 0' do
        expect(packet.buffer_length).to eq(0)
      end

      it 'sets #maximum_length to 0' do
        expect(packet.maximum_length).to eq(0)
      end
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

    context 'with a normal string' do
      it 'reads its own binary representation' do
        packet.assign('my_test')
        raw = packet.to_binary_s
        expect(described_class.read(raw)).to eq(packet)
        expect(described_class.read(raw).to_binary_s).to eq(raw)
      end
    end
  end

  describe '#set_maximum_length' do
    it 'sets buffer.max_count to the expected value' do
      packet.set_maximum_length(4)
      expect(packet.buffer.max_count).to eq(4 / 2)
    end

    it 'sets #maximum_length to the expected value' do
      packet.set_maximum_length(4)
      expect(packet.maximum_length).to eq(4)
    end
  end
end

RSpec.describe RubySMB::Dcerpc::PrrpUnicodeString do
  it 'is RrpUnicodeString subclass' do
    expect(described_class).to be < RubySMB::Dcerpc::RrpUnicodeString
  end

  subject(:packet) { described_class.new }

  it 'is a NDR pointer' do
    expect(subject).to be_a RubySMB::Dcerpc::Ndr::PointerPlugin
  end

  it { is_expected.to respond_to :ref_id }

  it 'is :null if #ref_id is zero' do
    packet.ref_id = 0
    expect(packet).to eq(:null)
  end

  describe '#read' do
    context 'with a null pointer' do
      it 'reads its own binary representation' do
        raw = packet.to_binary_s
        expect(described_class.read(raw)).to eq(packet)
        expect(described_class.read(raw).to_binary_s).to eq(raw)
      end
    end

    context 'with a normal string' do
      it 'reads its own binary representation' do
        packet.assign('my_test')
        raw = packet.to_binary_s
        expect(described_class.read(raw)).to eq(packet)
        expect(described_class.read(raw).to_binary_s).to eq(raw)
      end
    end
  end
end

RSpec.describe RubySMB::Dcerpc::RpcUnicodeString do
  subject(:packet) { described_class.new }

  it { is_expected.to respond_to :buffer_length }
  it { is_expected.to respond_to :maximum_length }
  it { is_expected.to respond_to :buffer }

  it 'is little endian' do
    expect(described_class.fields.instance_variable_get(:@hints)[:endian]).to eq :little
  end

  it 'has :byte_align parameter set to the expected value' do
    expect(described_class.default_parameters[:byte_align]).to eq(4)
  end

  describe '#buffer_length' do
    it 'should be a NdrUint16' do
      expect(packet.buffer_length).to be_a RubySMB::Dcerpc::Ndr::NdrUint16
    end
    it 'is 0 by default' do
      expect(packet.buffer_length).to eq(0)
    end
  end

  describe '#maximum_length' do
    it 'should be a NdrUint16' do
      expect(packet.maximum_length).to be_a RubySMB::Dcerpc::Ndr::NdrUint16
    end
    it 'is 0 by default' do
      expect(packet.maximum_length).to eq(0)
    end
  end

  describe '#buffer' do
    it 'should be a NdrWideStringPtr' do
      expect(packet.buffer).to be_a RubySMB::Dcerpc::Ndr::NdrWideStringPtr
    end
    it 'is :null by default' do
      expect(packet.buffer).to eq(:null)
    end
  end

  describe '#assign' do
    context 'with a string' do
      before :example do
        packet.assign('spec_test')
      end

      [BinData::Stringz, BinData::String, String].each do |klass|
        context "with a #{klass}" do
          it 'sets #buffer to the expected value' do
            expect(packet.buffer).to eq(RubySMB::Dcerpc::Ndr::NdrWideStringPtr.new('spec_test'))
          end

          it 'sets #buffer_length to the expected value' do
            expect(packet.buffer_length).to eq(('spec_test'.size) * 2)
          end

          it 'sets #maximum_length to the expected value' do
            expect(packet.maximum_length).to eq(('spec_test'.size) * 2)
          end
        end
      end
    end
    context 'with a :null pointer' do
      before :example do
        packet.assign(:null)
      end
      it 'sets #buffer to :null' do
        expect(packet.buffer).to eq(:null)
      end

      it 'sets #buffer_length to 0' do
        expect(packet.buffer_length).to eq(0)
      end

      it 'sets #maximum_length to 0' do
        expect(packet.maximum_length).to eq(0)
      end
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

    context 'with a normal string' do
      it 'reads its own binary representation' do
        packet.assign('my_test')
        raw = packet.to_binary_s
        expect(described_class.read(raw)).to eq(packet)
        expect(described_class.read(raw).to_binary_s).to eq(raw)
      end
    end
  end

  describe '#set_maximum_length' do
    it 'sets buffer.max_count to the expected value' do
      packet.set_maximum_length(4)
      expect(packet.buffer.max_count).to eq(4 / 2)
    end

    it 'sets #maximum_length to the expected value' do
      packet.set_maximum_length(4)
      expect(packet.maximum_length).to eq(4)
    end
  end
end

RSpec.describe RubySMB::Dcerpc::PrpcUnicodeString do
  it 'is RpcUnicodeString subclass' do
    expect(described_class).to be < RubySMB::Dcerpc::RpcUnicodeString
  end

  subject(:packet) { described_class.new }

  it 'is a NDR pointer' do
    expect(subject).to be_a RubySMB::Dcerpc::Ndr::PointerPlugin
  end

  it { is_expected.to respond_to :ref_id }

  it 'is :null if #ref_id is zero' do
    packet.ref_id = 0
    expect(packet).to eq(:null)
  end

  describe '#read' do
    context 'with a null pointer' do
      it 'reads its own binary representation' do
        raw = packet.to_binary_s
        expect(described_class.read(raw)).to eq(packet)
        expect(described_class.read(raw).to_binary_s).to eq(raw)
      end
    end

    context 'with a normal string' do
      it 'reads its own binary representation' do
        packet.assign('my_test')
        raw = packet.to_binary_s
        expect(described_class.read(raw)).to eq(packet)
        expect(described_class.read(raw).to_binary_s).to eq(raw)
      end
    end
  end
end
