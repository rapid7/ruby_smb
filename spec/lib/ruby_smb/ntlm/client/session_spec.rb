require 'spec_helper'

RSpec.describe RubySMB::NTLM::Client::Session do
  let(:message) { Net::NTLM::Message.decode64(%Q{
    TlRMTVNTUAACAAAADAAMADgAAAA1goni+fNfw+cInOgAAAAAAAAAAJoAmgBE
    AAAACgBjRQAAAA9NAFMARgBMAEEAQgACAAwATQBTAEYATABBAEIAAQAeAFcA
    SQBOAC0AMwBNAFMAUAA4AEsAMgBMAEMARwBDAAQAGABtAHMAZgBsAGEAYgAu
    AGwAbwBjAGEAbAADADgAVwBJAE4ALQAzAE0AUwBQADgASwAyAEwAQwBHAEMA
    LgBtAHMAZgBsAGEAYgAuAGwAbwBjAGEAbAAHAAgAS6UAWjxl2AEAAAAA
  }) }
  subject(:client) { RubySMB::NTLM::Client.new('rubysmb', 'rubysmb', flags: RubySMB::NTLM::DEFAULT_CLIENT_FLAGS) }
  subject(:session) { described_class.new(client, message) }

  describe '#authenticate!' do
    it 'calculates the user session key' do
      expect(session).to receive(:calculate_user_session_key!).and_call_original
      session.authenticate!
    end

    it 'checks if it is anonymous' do
      expect(session).to receive(:is_anonymous?).at_least(1).times.and_call_original
      session.authenticate!
    end

    it 'returns a Type3 message' do
      expect(session.authenticate!).to be_a Net::NTLM::Message::Type3
      expect(session.authenticate!).to be_a RubySMB::NTLM::Message
    end

    context 'when it is anonymous' do
      before(:each) { allow(session).to receive(:is_anonymous?).and_return(true) }
      after(:each) { session.authenticate! }

      it 'uses the correct lm response' do
        expect(session).to_not receive(:lmv2_resp)
        expect(Net::NTLM::Message::Type3).to receive(:create).and_wrap_original do |method, params|
          expect(params).to include :lm_response
          expect(params[:lm_response]).to eq "\x00".b
          method.call(params)
        end
      end

      it 'uses the correct ntlm response' do
        expect(session).to_not receive(:ntlmv2_resp)
        expect(Net::NTLM::Message::Type3).to receive(:create).and_wrap_original do |method, params|
          expect(params).to include :ntlm_response
          expect(params[:ntlm_response]).to eq ''
          method.call(params)
        end
      end
    end

    context 'when it is not anonymous' do
      before(:each) { allow(session).to receive(:is_anonymous?).and_return(false) }
      after(:each) { session.authenticate! }

      it 'uses the correct lm response' do
        expect(session).to receive(:lmv2_resp).and_call_original
        expect(Net::NTLM::Message::Type3).to receive(:create).and_wrap_original do |method, params|
          expect(params).to include :lm_response
          expect(params[:lm_response].length).to be > 16
          method.call(params)
        end
      end

      it 'uses the correct ntlm response' do
        expect(session).to receive(:ntlmv2_resp).and_call_original
        expect(Net::NTLM::Message::Type3).to receive(:create).and_wrap_original do |method, params|
          expect(params).to include :ntlm_response
          expect(params[:ntlm_response].length).to be > 16
          method.call(params)
        end
      end
    end
  end

  describe '#calculate_user_session_key!' do
    it 'returns an all zero key when it is anonymous' do
      expect(session).to receive(:is_anonymous?).and_return(true)
      expect(session.send(:calculate_user_session_key!)).to eq "\x00".b * 16
    end

    it 'returns a session key' do
      expect(session).to receive(:is_anonymous?).and_return(false)
      expect(session.send(:calculate_user_session_key!)).to_not eq "\x00".b * 16
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
