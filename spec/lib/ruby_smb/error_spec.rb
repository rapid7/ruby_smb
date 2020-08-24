require 'spec_helper'

RSpec.describe RubySMB::Error::InvalidPacket do
  context 'with a String' do
    it 'outputs the expected error message' do
      ex = described_class.new('My exception')
      expect(ex.to_s).to eq('My exception')
    end
  end

  context 'with a Hash' do
    let(:ex) do
      described_class.new(
        expected_proto:  RubySMB::SMB1::SMB_PROTOCOL_ID,
        expected_cmd:    RubySMB::SMB1::Packet::NegotiateResponseExtended::COMMAND,
        expected_custom: "extended_security=1",
        packet:          packet,
        received_custom: "extended_security=0"
      )
    end

    context 'with an SMB2 packet' do
      let(:packet) { RubySMB::SMB2::Packet::NegotiateResponse.new }

      it 'outputs the expected error message' do
        expect(ex.to_s).to eq('Expecting SMB1 protocol with command=114 (extended_security=1), got SMB2 protocol with command=0 (extended_security=0), Status: (0x00000000) STATUS_SUCCESS: The operation completed successfully.')
      end
    end

    context 'with an SMB1 packet' do
      let(:packet) { RubySMB::SMB1::Packet::ReadAndxRequest.new }

      it 'outputs the expected error message' do
        expect(ex.to_s).to eq('Expecting SMB1 protocol with command=114 (extended_security=1), got SMB1 protocol with command=46 (extended_security=0), Status: (0x00000000) STATUS_SUCCESS: The operation completed successfully.')
      end
    end

    context 'without packet' do
      let(:ex) do
        described_class.new(
          expected_proto:  RubySMB::SMB1::SMB_PROTOCOL_ID,
          expected_cmd:    RubySMB::SMB1::Packet::NegotiateResponseExtended::COMMAND,
          expected_custom: "extended_security=1",
          received_custom: "extended_security=0"
        )
      end

      it 'outputs the expected error message' do
        expect(ex.to_s).to eq('Expecting SMB1 protocol with command=114 (extended_security=1), got ??? protocol with command=??? (extended_security=0)')
      end
    end
  end

  context 'with an unsupported type' do
    it 'raises the expected exception' do
      expect { described_class.new(['wrong']) }.to raise_error(
        ArgumentError,
        'InvalidPacket expects a String or a Hash, got a Array'
      )
    end
  end
end


RSpec.describe RubySMB::Error::UnexpectedStatusCode do
  context 'with a WindowsError::ErrorCode' do
    it 'outputs the expected error message' do
      ex = described_class.new(WindowsError::NTStatus::STATUS_BUFFER_OVERFLOW)
      expect(ex.to_s).to eq('The server responded with an unexpected status code: STATUS_BUFFER_OVERFLOW')
    end
  end

  context 'with an Integer' do
    it 'outputs the expected error message' do
      ex = described_class.new(0x80000005)
      expect(ex.to_s).to eq('The server responded with an unexpected status code: STATUS_BUFFER_OVERFLOW')
    end
  end

  context 'with an unsupported type' do
    it 'raises the expected exception' do
      expect { described_class.new(['wrong']) }.to raise_error(
        ArgumentError,
        'Status code must be a WindowsError::ErrorCode or an Integer, got Array'
      )
    end
  end
end
