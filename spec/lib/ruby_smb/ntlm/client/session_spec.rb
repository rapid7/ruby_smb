require 'spec_helper'

RSpec.describe RubySMB::NTLM::Client::Session do
  let(:message) { Net::NTLM::Message.decode64(%Q{
    TlRMTVNTUAACAAAADAAMADgAAAA1goni+fNfw+cInOgAAAAAAAAAAJoAmgBE
    AAAACgBjRQAAAA9NAFMARgBMAEEAQgACAAwATQBTAEYATABBAEIAAQAeAFcA
    SQBOAC0AMwBNAFMAUAA4AEsAMgBMAEMARwBDAAQAGABtAHMAZgBsAGEAYgAu
    AGwAbwBjAGEAbAADADgAVwBJAE4ALQAzAE0AUwBQADgASwAyAEwAQwBHAEMA
    LgBtAHMAZgBsAGEAYgAuAGwAbwBjAGEAbAAHAAgAS6UAWjxl2AEAAAAA
  }) }
  let(:username) { 'rubysmb' }
  let(:password) { 'rubysmb' }
  let(:client) { RubySMB::NTLM::Client.new(username, password, flags: RubySMB::NTLM::DEFAULT_CLIENT_FLAGS) }
  subject(:session) { described_class.new(client, message) }

  describe '#authenticate!' do
    it 'calculates the user session key' do
      expect(session).to receive(:calculate_user_session_key!).and_call_original
      session.authenticate!
    end

    it 'returns a Type3 message' do
      expect(session.authenticate!).to be_a Net::NTLM::Message::Type3
      expect(session.authenticate!).to be_a Net::NTLM::Message
    end

    context 'when it is anonymous' do
      let(:username) { '' }
      let(:password) { '' }

      it 'uses the correct lm response' do
        expect(session.authenticate!.lm_response).to eq "\x00".b
      end

      it 'uses the correct ntlm response' do
        expect(session.authenticate!.ntlm_response).to eq ''
      end
    end

    context 'when it is not anonymous' do
      it 'uses the correct lm response' do
        expect(session.authenticate!.lm_response.length).to be > 16
      end

      it 'uses the correct ntlm response' do
        expect(session.authenticate!.ntlm_response.length).to be > 16
      end
    end
  end

  describe '#calculate_user_session_key!' do
    context 'when it is anonymous' do
      let(:username) { '' }
      let(:password) { '' }

      it 'returns an all zero key' do
        expect(session.send(:calculate_user_session_key!)).to eq "\x00".b * 16
      end
    end

    it 'returns a session key' do
      session_key = session.send(:calculate_user_session_key!)
      expect(session_key.bytesize).to eq 16
      expect(session_key).to_not eq "\x00".b * 16
    end
  end

  describe '#is_anonymous?' do
    it 'returns false when the username is not blank' do
      allow(session).to receive(:username).and_return('username')
      allow(session).to receive(:password).and_return('')
      expect(session.is_anonymous?).to be false
    end

    it 'returns false when the password is not blank' do
      allow(session).to receive(:username).and_return('')
      allow(session).to receive(:password).and_return('password')
      expect(session.is_anonymous?).to be false
    end

    it 'returns false when the username is not blank and the password is not blank' do
      allow(session).to receive(:username).and_return('username')
      allow(session).to receive(:password).and_return('password')
      expect(session.is_anonymous?).to be false
    end

    it 'returns true when the username is blank and the password is blank' do
      allow(session).to receive(:username).and_return('')
      allow(session).to receive(:password).and_return('')
      expect(session.is_anonymous?).to be true
    end
  end
end
