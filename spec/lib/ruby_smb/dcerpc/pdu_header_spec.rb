RSpec.describe RubySMB::Dcerpc::PDUHeader do
  subject(:packet) { described_class.new }

  it { is_expected.to respond_to :rpc_vers }
  it { is_expected.to respond_to :rpc_vers_minor }
  it { is_expected.to respond_to :ptype }
  it { is_expected.to respond_to :pfc_flags }
  it { is_expected.to respond_to :packed_drep }
  it { is_expected.to respond_to :frag_length }
  it { is_expected.to respond_to :auth_length }
  it { is_expected.to respond_to :call_id }

  it 'is little endian' do
    expect(described_class.fields.instance_variable_get(:@hints)[:endian]).to eq :little
  end

  describe '#rpc_vers' do
    it 'should be a 8-bit unsigned integer' do
      expect(packet.rpc_vers).to be_a BinData::Uint8
    end

    it 'should have a default value of 5' do
      expect(packet.rpc_vers).to eq 5
    end
  end

  describe '#rpc_vers_minor' do
    it 'should be a 8-bit unsigned integer' do
      expect(packet.rpc_vers_minor).to be_a BinData::Uint8
    end
  end

  describe '#ptype' do
    it 'should be a 8-bit unsigned integer' do
      expect(packet.ptype).to be_a BinData::Uint8
    end
  end

  describe '#pfc_flags' do
    subject(:pfc_flags) { packet.pfc_flags }

    it 'should be a custom structure' do
      expect(pfc_flags).to be_a BinData::Struct
    end

    it { is_expected.to respond_to :object_uuid }
    it { is_expected.to respond_to :maybe }
    it { is_expected.to respond_to :did_not_execute }
    it { is_expected.to respond_to :conc_mpx }
    it { is_expected.to respond_to :reserved_1 }
    it { is_expected.to respond_to :support_header_sign }
    it { is_expected.to respond_to :last_frag }
    it { is_expected.to respond_to :first_frag }
  end

  describe '#packed_drep' do
    it 'should be a 32-bit unsigned integer' do
      expect(packet.packed_drep).to be_a BinData::Uint32le
    end

    it 'should have a default value of 0x10' do
      expect(packet.packed_drep).to eq 0x10
    end
  end

  describe '#frag_length' do
    it 'should be a 16-bit unsigned integer' do
      expect(packet.frag_length).to be_a BinData::Uint16le
    end

    it 'should be the size of the full packet' do
      bind_ack = RubySMB::Dcerpc::BindAck.new
      expect(bind_ack.pdu_header.frag_length).to eq(bind_ack.do_num_bytes)
    end
  end

  describe '#auth_length' do
    it 'should be a 16-bit unsigned integer' do
      expect(packet.auth_length).to be_a BinData::Uint16le
    end
  end

  describe '#call_id' do
    it 'should be a 32-bit unsigned integer' do
      expect(packet.call_id).to be_a BinData::Uint32le
    end

    it 'should have a default value of 1' do
      expect(packet.call_id).to eq 1
    end
  end

  it 'reads its own binary representation and output the same packet' do
    packet = described_class.new(
      rpc_vers: rand(0xFF),
      rpc_vers_minor: rand(0xFF),
      ptype: rand(0xFF),
      pfc_flags: { support_header_sign: 1},
      packed_drep: rand(0xFF),
      frag_length: rand(0xFF),
      auth_length: rand(0xFF),
      call_id: rand(0xFF)
    )
    binary = packet.to_binary_s
    expect(described_class.read(binary)).to eq(packet)
  end

end


