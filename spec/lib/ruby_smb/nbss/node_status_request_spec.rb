require 'spec_helper'

RSpec.describe RubySMB::Nbss::NodeStatusRequest do
  subject(:request) { described_class.new(transaction_id: 0x1234) }

  before :example do
    request.question_name.set("*".ljust(16, "\x00"))
  end

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
end
