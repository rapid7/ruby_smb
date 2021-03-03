RSpec.describe RubySMB::Dcerpc::RrpUnicodeString do
  subject(:packet) { described_class.new }

  it { is_expected.to respond_to :buffer_length }
  it { is_expected.to respond_to :maximum_length }
  it { is_expected.to respond_to :buffer }

  it 'is little endian' do
    expect(described_class.fields.instance_variable_get(:@hints)[:endian]).to eq :little
  end

  describe '#buffer_length' do
    it 'should be a 16-bit unsigned integer' do
      expect(packet.buffer_length).to be_a BinData::Uint16le
    end
  end

  describe '#maximum_length' do
    it 'should be a 16-bit unsigned integer' do
      expect(packet.maximum_length).to be_a BinData::Uint16le
    end
  end

  describe '#buffer' do
    it 'should be a WideStringPtr' do
      expect(packet.buffer).to be_a RubySMB::Dcerpc::Ndr::WideStringPtr
    end
  end

  describe '#get' do
    it 'returns #buffer' do
      packet.buffer = 'spec_test'
      expect(packet.get).to eq(RubySMB::Dcerpc::Ndr::WideStringPtr.new('spec_test'))
    end
  end

  describe '#set' do
    it 'sets #buffer to the expected value' do
      packet.set('spec_test')
      expect(packet.buffer).to eq(RubySMB::Dcerpc::Ndr::WideStringPtr.new('spec_test'))
    end

    it 'sets #buffer_length to the expected value' do
      packet.set('spec_test')
      expect(packet.buffer_length).to eq(('spec_test'.size) * 2)
    end

    it 'sets #maximum_length to the expected value' do
      packet.set('spec_test')
      expect(packet.maximum_length).to eq(('spec_test'.size) * 2)
    end

    context 'when the value is :null' do
      it 'sets #buffer_length to 0' do
        packet.buffer_length = 33
        packet.set(:null)
        expect(packet.buffer_length).to eq(0)
      end

      it 'does not set #maximum_length if it has already been set' do
        packet.maximum_length = 33
        packet.set(:null)
        expect(packet.maximum_length).to eq(33)
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
end

RSpec.describe RubySMB::Dcerpc::PrrpUnicodeString do
  it 'is RrpUnicodeString subclass' do
    expect(described_class).to be < RubySMB::Dcerpc::RrpUnicodeString
  end

  subject(:packet) { described_class.new }

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
