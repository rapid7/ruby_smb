require 'spec_helper'

RSpec.describe RubySMB::Nbss::NodeStatusRequest do
  subject(:request) { described_class.new(transaction_id: 0x1234) }

  describe 'encoded bytes' do
    let(:bytes) { request.to_binary_s }

    it 'starts with a 12-byte NBNS header' do
      expect(bytes[0, 2].unpack1('n')).to eq(0x1234)
      expect(bytes[2, 2].unpack1('n')).to eq(0x0000)  # flags
      expect(bytes[4, 2].unpack1('n')).to eq(1)       # qdcount
      expect(bytes[6, 2].unpack1('n')).to eq(0)       # ancount
      expect(bytes[8, 2].unpack1('n')).to eq(0)       # nscount
      expect(bytes[10, 2].unpack1('n')).to eq(0)      # arcount
    end

    it 'encodes the wildcard question name as 34 bytes (length + 32-char L1 + null)' do
      expect(bytes[12].unpack1('C')).to eq(0x20)   # label length
      expect(bytes[13, 32]).to eq('CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA')
      expect(bytes[45].unpack1('C')).to eq(0x00)   # null label terminator
    end

    it 'ends with QTYPE=NBSTAT and QCLASS=IN' do
      expect(bytes[46, 2].unpack1('n')).to eq(described_class::QUESTION_TYPE_NBSTAT)
      expect(bytes[48, 2].unpack1('n')).to eq(described_class::QUESTION_CLASS_IN)
    end

    it 'is exactly 50 bytes long' do
      expect(bytes.bytesize).to eq(50)
    end
  end

  describe 'flags' do
    it 'packs the OPCODE, NM_FLAGS and RCODE fields in RFC bit order' do
      request.opcode.response = 1
      request.nm_flags.authoritative_answer = 1
      request.nm_flags.broadcast = 1
      request.rcode.rcode = 0x5

      expect(request.to_binary_s[2, 2].unpack1('n')).to eq(0x8415)
    end

    it 'defaults every request flag bit to zero' do
      expect(request.to_binary_s[2, 2].unpack1('n')).to eq(0x0000)
      expect(request.opcode.response.to_i).to eq(0)
      expect(request.opcode.opcode.to_i).to eq(0)
      expect(request.nm_flags.broadcast.to_i).to eq(0)
      expect(request.rcode.rcode.to_i).to eq(0)
    end
  end
end
