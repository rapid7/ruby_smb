require 'spec_helper'

RSpec.describe RubySMB::NTLM::Client do
  subject(:client) { described_class.new('rubysmb', 'rubysmb', flags: RubySMB::NTLM::DEFAULT_CLIENT_FLAGS) }

  describe '#init_context' do
    context 'when a response is provided' do
      let(:resp) { %Q{
        TlRMTVNTUAACAAAADAAMADgAAAA1goni+fNfw+cInOgAAAAAAAAAAJoAmgBE
        AAAACgBjRQAAAA9NAFMARgBMAEEAQgACAAwATQBTAEYATABBAEIAAQAeAFcA
        SQBOAC0AMwBNAFMAUAA4AEsAMgBMAEMARwBDAAQAGABtAHMAZgBsAGEAYgAu
        AGwAbwBjAGEAbAADADgAVwBJAE4ALQAzAE0AUwBQADgASwAyAEwAQwBHAEMA
        LgBtAHMAZgBsAGEAYgAuAGwAbwBjAGEAbAAHAAgAS6UAWjxl2AEAAAAA
      } }
      it 'returns a Type3 message' do
        expect(client.init_context(resp)).to be_a Net::NTLM::Message::Type3
      end

      it 'creates a new session object' do
        expect(RubySMB::NTLM::Client::Session).to receive(:new).and_call_original
        client.init_context(resp)
      end
    end

    context 'when a response is not provided' do
      it 'returns a Type1 message' do
        expect(client.init_context).to be_a Net::NTLM::Message::Type1
      end

      it 'does not create a new session object' do
        expect(RubySMB::NTLM::Client::Session).to_not receive(:new)
        client.init_context
      end
    end
  end
end
