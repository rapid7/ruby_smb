RSpec.describe RubySMB::SMB2::Packet::NegotiateResponse do
  subject(:packet) { described_class.new }

  it { is_expected.to respond_to :smb2_header }
  it { is_expected.to respond_to :structure_size }
  it { is_expected.to respond_to :security_mode }
  it { is_expected.to respond_to :dialect_revision }
  it { is_expected.to respond_to :negotiate_context_count }
  it { is_expected.to respond_to :server_guid }
  it { is_expected.to respond_to :capabilities }
  it { is_expected.to respond_to :max_transact_size }
  it { is_expected.to respond_to :max_read_size }
  it { is_expected.to respond_to :max_write_size }
  it { is_expected.to respond_to :system_time }
  it { is_expected.to respond_to :server_start_time }
  it { is_expected.to respond_to :security_buffer_offset }
  it { is_expected.to respond_to :security_buffer_length }
  it { is_expected.to respond_to :negotiate_context_offset }
  it { is_expected.to respond_to :security_buffer }

  it 'is little endian' do
    expect(described_class.fields.instance_variable_get(:@hints)[:endian]).to eq :little
  end

  describe '#smb2_header' do
    subject(:header) { packet.smb2_header }

    it 'is a standard SMB Header' do
      expect(header).to be_a RubySMB::SMB2::SMB2Header
    end

    it 'should have the command set to SMB_COM_NEGOTIATE' do
      expect(header.command).to eq RubySMB::SMB2::Commands::NEGOTIATE
    end

    it 'should have the response flag set' do
      expect(header.flags.reply).to eq 1
    end
  end

  describe '#structure_size' do
    it 'should be a 16-bit unsigned integer' do
      expect(packet.structure_size).to be_a BinData::Uint16le
    end

    it 'should have a default value of 65 as per the SMB2 spec' do
      expect(packet.structure_size).to eq 65
    end
  end

  describe '#security_mode' do
    it 'should be a SMB2 Security Mode BitField' do
      expect(packet.security_mode).to be_a RubySMB::SMB2::BitField::Smb2SecurityMode
    end
  end

  describe '#dialect_revision' do
    it 'is a 16-bit unsigned integer' do
      expect(packet.dialect_revision).to be_a BinData::Uint16le
    end
  end

  describe '#negotiate_context_count' do
    it 'only exists if the 0x0311 dialect is included' do
      packet.dialect_revision = 0x0311
      expect(packet.negotiate_context_count?).to be true
    end

    it 'does not exist if the 0x0311 dialect is not included' do
      packet.dialect_revision = 0x0300
      expect(packet.negotiate_context_count?).to be false
    end

    it 'is a 16-bit unsigned integer' do
      expect(packet.negotiate_context_count).to be_a BinData::Uint16le
    end

    it 'is set to the #negotiate_context_list array sise' do
      packet.dialect_revision = 0x0311
      nc = RubySMB::SMB2::NegotiateContext.new(
        context_type: RubySMB::SMB2::NegotiateContext::SMB2_PREAUTH_INTEGRITY_CAPABILITIES
      )
      packet.negotiate_context_list << nc
      packet.negotiate_context_list << nc
      expect(packet.negotiate_context_count).to eq(2)
    end
  end

  describe '#server_guid' do
    it 'should be a binary string' do
      expect(packet.server_guid).to be_a BinData::String
    end

    it 'should be 16-bytes' do
      expect(packet.server_guid.do_num_bytes).to eq 16
    end
  end

  describe '#capabilities' do
    it 'should be a SMB2 Capabilities BitField' do
      expect(packet.capabilities).to be_a RubySMB::SMB2::BitField::Smb2Capabilities
    end
  end

  describe '#max_transact_size' do
    it 'is a 32-bit unsigned integer' do
      expect(packet.max_transact_size).to be_a BinData::Uint32le
    end
  end

  describe '#max_read_size' do
    it 'is a 32-bit unsigned integer' do
      expect(packet.max_read_size).to be_a BinData::Uint32le
    end
  end

  describe '#max_write_size' do
    it 'is a 32-bit unsigned integer' do
      expect(packet.max_write_size).to be_a BinData::Uint32le
    end
  end

  describe '#system_time' do
    it 'should be a Filetime field' do
      expect(packet.system_time).to be_a RubySMB::Field::FileTime
    end
  end

  describe '#server_start_time' do
    it 'should be a Filetime field' do
      expect(packet.server_start_time).to be_a RubySMB::Field::FileTime
    end
  end

  describe '#security_buffer_offset' do
    it 'is a 16-bit unsigned integer' do
      expect(packet.security_buffer_offset).to be_a BinData::Uint16le
    end
  end

  describe '#security_buffer_length' do
    it 'is a 16-bit unsigned integer' do
      expect(packet.security_buffer_length).to be_a BinData::Uint16le
    end

    it 'should be the length of the security_buffer field' do
      packet.security_buffer = 'foobar'
      expect(packet.security_buffer_length).to eq 6
    end
  end

  describe '#negotiate_context_offset' do
    it 'only exists if the 0x0311 dialect is included' do
      packet.dialect_revision = 0x0311
      expect(packet.negotiate_context_offset?).to be true
    end

    it 'does not exist if the 0x0311 dialect is not included' do
      packet.dialect_revision = 0x0300
      expect(packet.negotiate_context_offset?).to be false
    end

    it 'is a 32-bit unsigned integer' do
      expect(packet.negotiate_context_offset).to be_a BinData::Uint32le
    end
  end

  describe '#security_buffer' do
    it 'should be a binary string' do
      expect(packet.security_buffer).to be_a BinData::String
    end
  end

  describe '#pad' do
    it 'only exists if the 0x0311 dialect is included' do
      packet.dialect_revision = 0x0311
      expect(packet.pad?).to be true
    end

    it 'does not exist if the 0x0311 dialect is not included' do
      packet.dialect_revision = 0x0300
      expect(packet.pad?).to be false
    end

    it 'should be a binary string' do
      expect(packet.pad).to be_a BinData::String
    end

    it 'should keep #negotiate_context_list 8-byte aligned' do
      packet.dialect_revision = 0x0311
      expect(packet.negotiate_context_list.abs_offset % 8).to eq 0
    end
  end

  describe '#negotiate_context_list' do
    it 'only exists if the 0x0311 dialect is included' do
      packet.dialect_revision = 0x0311
      expect(packet.negotiate_context_list?).to be true
    end

    it 'does not exist if the 0x0311 dialect is not included' do
      packet.dialect_revision = 0x0300
      expect(packet.negotiate_context_list?).to be false
    end

    it 'is an array field as per the SMB spec' do
      expect(packet.negotiate_context_list).to be_a BinData::Array
    end
  end

  describe '#find_negotiate_context' do
    before :example do
      packet.add_negotiate_context(
        RubySMB::SMB2::NegotiateContext.new(context_type: RubySMB::SMB2::NegotiateContext::SMB2_PREAUTH_INTEGRITY_CAPABILITIES)
      )
      packet.add_negotiate_context(
        RubySMB::SMB2::NegotiateContext.new(context_type: RubySMB::SMB2::NegotiateContext::SMB2_ENCRYPTION_CAPABILITIES)
      )
    end

    it 'returns the expected Negotiate Context structure' do
      expect(packet.find_negotiate_context(RubySMB::SMB2::NegotiateContext::SMB2_ENCRYPTION_CAPABILITIES)).to eq(packet.negotiate_context_list[1])
    end

    it 'returns nil if the Negotiate Context structure is not found' do
      expect(packet.find_negotiate_context(10)).to be nil
    end
  end

  describe '#add_negotiate_context' do
    it 'raises an ArgumentError exception if it is not a NegotiateContext structure' do
      expect { packet.add_negotiate_context('nc') }.to raise_error(ArgumentError)
    end

    it 'updates the NegotiateContext#pad length to make sure the structure is 8-byte aligned' do
      packet.dialect_revision = 0x0311
      [
        RubySMB::SMB2::NegotiateContext::SMB2_PREAUTH_INTEGRITY_CAPABILITIES,
        RubySMB::SMB2::NegotiateContext::SMB2_ENCRYPTION_CAPABILITIES,
        RubySMB::SMB2::NegotiateContext::SMB2_COMPRESSION_CAPABILITIES,
        RubySMB::SMB2::NegotiateContext::SMB2_NETNAME_NEGOTIATE_CONTEXT_ID
      ].each do |context_type|
        nc = RubySMB::SMB2::NegotiateContext.new(context_type: context_type)
        packet.add_negotiate_context(nc)
        expect(packet.negotiate_context_list.last.context_type.abs_offset % 8).to eq 0
      end
    end
  end

  it 'reads binary data as expected' do
    data = described_class.new
    data.dialect_revision = 0x0311
    data.security_buffer = 'security buf test'
    [
      RubySMB::SMB2::NegotiateContext::SMB2_PREAUTH_INTEGRITY_CAPABILITIES,
      RubySMB::SMB2::NegotiateContext::SMB2_ENCRYPTION_CAPABILITIES,
      RubySMB::SMB2::NegotiateContext::SMB2_COMPRESSION_CAPABILITIES,
      RubySMB::SMB2::NegotiateContext::SMB2_NETNAME_NEGOTIATE_CONTEXT_ID
    ].each do |context_type|
      nc = RubySMB::SMB2::NegotiateContext.new(context_type: context_type)
      data.add_negotiate_context(nc)
      expect(described_class.read(data.to_binary_s)).to eq(data)
    end
  end
end
