RSpec.describe RubySMB::Gss::Provider::Kerberos do
  let(:server_client) { double('server_client', logger: Logger.new(IO::NULL)) }
  # opaque stand-in for a real AP-REQ; this provider never interprets the payload
  let(:ap_req) { "\x6e\x82\x01\x0a".b + Random.new(1).bytes(64) }
  let(:mech_token) { RubySMB::Gss::Provider::Kerberos::TOK_ID_KRB_AP_REQ + ap_req }

  subject(:provider) { RubySMB::Gss::Provider::Kerberos.new }

  describe '#mech_types' do
    it 'advertises both the standard and the Microsoft Kerberos mechanism' do
      expect(provider.mech_types.map(&:oid)).to eq(
        [RubySMB::Gss::OID_KERBEROS_5.oid, RubySMB::Gss::OID_MICROSOFT_KERBEROS_5.oid]
      )
    end

    it 'reports support for both' do
      expect(provider.supports_mech_type?(RubySMB::Gss::OID_KERBEROS_5)).to be true
      expect(provider.supports_mech_type?(RubySMB::Gss::OID_MICROSOFT_KERBEROS_5)).to be true
    end

    it 'does not report support for other mechanisms' do
      expect(provider.supports_mech_type?(RubySMB::Gss::OID_NTLMSSP)).to be false
    end
  end

  describe '.token_id' do
    # a GSS-API InitialContextToken, shaped as a Windows client actually sends one: the token id follows the
    # mechanism OID rather than starting the token, and the framing around it is not valid ASN.1
    let(:initial_context_token) do
      "\x60\x82\x0c\x0e".b +
        OpenSSL::ASN1::ObjectId.new('1.2.840.113554.1.2.2').to_der +
        RubySMB::Gss::Provider::Kerberos::TOK_ID_KRB_AP_REQ +
        "\x6e\x82\x0b\xfd".b
    end

    it 'reads the identifier from past the mechanism OID' do
      expect(RubySMB::Gss::Provider::Kerberos.token_id(initial_context_token))
        .to eq(RubySMB::Gss::Provider::Kerberos::TOK_ID_KRB_AP_REQ)
    end

    it 'handles a short form length' do
      short = "\x60\x14".b + OpenSSL::ASN1::ObjectId.new('1.2.840.113554.1.2.2').to_der +
              RubySMB::Gss::Provider::Kerberos::TOK_ID_KRB_AP_REP + "\x6f\x00".b
      expect(RubySMB::Gss::Provider::Kerberos.token_id(short))
        .to eq(RubySMB::Gss::Provider::Kerberos::TOK_ID_KRB_AP_REP)
    end

    it 'is nil for anything not shaped like an InitialContextToken' do
      expect(RubySMB::Gss::Provider::Kerberos.token_id(nil)).to be_nil
      expect(RubySMB::Gss::Provider::Kerberos.token_id('')).to be_nil
      expect(RubySMB::Gss::Provider::Kerberos.token_id('short')).to be_nil
      # a SEQUENCE rather than an InitialContextToken
      expect(RubySMB::Gss::Provider::Kerberos.token_id("\x30\x82\x00\x05".b)).to be_nil
    end

    it 'is nil when no mechanism OID follows' do
      expect(RubySMB::Gss::Provider::Kerberos.token_id("\x60\x04\x02\x01\x05\x00".b)).to be_nil
    end
  end

  describe '#on_mech_token' do
    it 'can be set with a block' do
      provider.on_mech_token { |_token, _authenticator| :handled }
      expect(provider.on_mech_token('token', nil)).to eq(:handled)
    end

    it 'can be set through the constructor' do
      configured = RubySMB::Gss::Provider::Kerberos.new { |_token, _authenticator| :handled }
      expect(configured.on_mech_token('token', nil)).to eq(:handled)
    end

    it 'is nil when no handler has been set' do
      expect(provider.on_mech_token('token', nil)).to be_nil
    end
  end

  # referenced explicitly; described_class would resolve to the authenticator inside this group
  describe RubySMB::Gss::Provider::Kerberos::Authenticator do
    subject(:authenticator) { provider.new_authenticator(server_client) }

    describe '#process' do
      context 'when building the advertisement' do
        it 'offers the Kerberos mechanisms' do
          expect(authenticator.process(nil).buffer).to eq(RubySMB::Gss.gss_neg_token_init(provider.mech_types))
        end

        it 'succeeds' do
          expect(authenticator.process(nil).nt_status).to eq(WindowsError::NTStatus::STATUS_SUCCESS)
        end
      end

      context 'with a mechanism token' do
        it 'passes the token to the handler' do
          received = nil
          provider.on_mech_token { |token, _authenticator| received = token; nil }
          authenticator.process(neg_token_init(mech_token))
          expect(received).to eq(mech_token)
        end

        it 'does not alter the token, so a forwarded ticket stays valid' do
          received = nil
          provider.on_mech_token { |token, _authenticator| received = token; nil }
          authenticator.process(neg_token_init(mech_token))
          expect(received).to eq(mech_token)
          expect(received[2..]).to eq(ap_req)
        end

        it 'records the token on the authenticator' do
          authenticator.process(neg_token_init(mech_token))
          expect(authenticator.mech_token).to eq(mech_token)
        end

        it 'returns whatever the handler decides' do
          expected = RubySMB::Gss::Provider::Result.new(nil, WindowsError::NTStatus::STATUS_SUCCESS)
          provider.on_mech_token { |_token, _authenticator| expected }
          expect(authenticator.process(neg_token_init(mech_token))).to be(expected)
        end

        it 'refuses the attempt when no handler is set' do
          # nothing here can validate a ticket, so the attempt must not silently succeed
          result = authenticator.process(neg_token_init(mech_token))
          expect(result.nt_status).to eq(WindowsError::NTStatus::STATUS_LOGON_FAILURE)
        end

        it 'refuses the attempt when the handler returns something that is not a Result' do
          # the session setup path calls nt_status on the result, so a non-Result (e.g. a boolean from a naive
          # handler) must be refused here rather than handed on to crash the caller
          provider.on_mech_token { |_token, _authenticator| true }
          result = authenticator.process(neg_token_init(mech_token))
          expect(result).to be_a(RubySMB::Gss::Provider::Result)
          expect(result.nt_status).to eq(WindowsError::NTStatus::STATUS_LOGON_FAILURE)
        end

        it 'accepts a token carried in a continuation' do
          received = nil
          provider.on_mech_token { |token, _authenticator| received = token; nil }
          authenticator.process(RubySMB::Gss.gss_type3(mech_token))
          expect(received).to eq(mech_token)
        end
      end

      context 'with a malformed request' do
        it 'returns nil rather than raising' do
          expect(authenticator.process('not asn1 at all')).to be_nil
        end

        it 'returns nil when there is no mechanism token' do
          expect(authenticator.process(neg_token_init(nil))).to be_nil
        end
      end
    end

    describe '#reset!' do
      it 'forgets the recorded token' do
        authenticator.process(neg_token_init(mech_token))
        expect(authenticator.mech_token).to_not be_nil
        authenticator.reset!
        expect(authenticator.mech_token).to be_nil
      end
    end
  end

  describe 'alongside NTLM' do
    let(:ntlm_provider) { RubySMB::Gss::Provider::NTLM.new.tap { |p| p.put_account('RubySMB', 'password') } }
    let(:multi) { RubySMB::Gss::Provider::Multi.new([provider, ntlm_provider]) }

    it 'is offered ahead of NTLM' do
      expect(multi.mech_types.map(&:oid)).to eq(
        [
          RubySMB::Gss::OID_KERBEROS_5.oid,
          RubySMB::Gss::OID_MICROSOFT_KERBEROS_5.oid,
          RubySMB::Gss::OID_NTLMSSP.oid
        ]
      )
    end

    it 'receives the token when a client selects Kerberos' do
      received = nil
      provider.on_mech_token { |token, _authenticator| received = token; nil }
      multi.new_authenticator(server_client).process(neg_token_init(mech_token))
      expect(received).to eq(mech_token)
    end

    it 'is left alone when a client selects NTLM' do
      received = nil
      provider.on_mech_token { |token, _authenticator| received = token; nil }
      type1 = Net::NTLM::Message::Type1.new.tap { |msg| msg.domain = 'WORKGROUP' }
      result = multi.new_authenticator(server_client).process(RubySMB::Gss.gss_type1(type1.serialize))
      expect(received).to be_nil
      expect(result.nt_status).to eq(WindowsError::NTStatus::STATUS_MORE_PROCESSING_REQUIRED)
    end
  end

  # Build a SPNEGO NegTokenInit selecting Kerberos and carrying the specified mechanism token.
  def neg_token_init(token)
    inner = [OpenSSL::ASN1::ASN1Data.new([OpenSSL::ASN1::Sequence.new([RubySMB::Gss::OID_KERBEROS_5])], 0, :CONTEXT_SPECIFIC)]
    inner << OpenSSL::ASN1::ASN1Data.new([OpenSSL::ASN1::OctetString.new(token)], 2, :CONTEXT_SPECIFIC) unless token.nil?

    OpenSSL::ASN1::ASN1Data.new(
      [
        RubySMB::Gss::OID_SPNEGO,
        OpenSSL::ASN1::ASN1Data.new([OpenSSL::ASN1::Sequence.new(inner)], 0, :CONTEXT_SPECIFIC)
      ], 0, :APPLICATION
    ).to_der
  end
end
