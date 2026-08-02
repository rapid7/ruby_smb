RSpec.describe RubySMB::Gss::Provider::Multi do
  let(:username) { 'RubySMB' }
  let(:domain) { 'WORKGROUP' }
  let(:password) { 'password' }
  let(:ntlm_provider) do
    RubySMB::Gss::Provider::NTLM.new.tap { |provider| provider.put_account(username, password, domain: domain) }
  end
  let(:other_authenticator) { double('authenticator', process: nil, reset!: nil, session_key: nil) }
  # a stand-in for any non-NTLM mechanism, so the routing can be exercised without a second real provider
  let(:other_provider) do
    authenticator = other_authenticator
    Class.new(RubySMB::Gss::Provider::Base) do
      define_method(:mech_types) do
        [RubySMB::Gss::OID_KERBEROS_5, RubySMB::Gss::OID_MICROSOFT_KERBEROS_5]
      end

      define_method(:new_authenticator) { |_server_client| authenticator }
    end.new
  end
  let(:server_client) { double('server_client', logger: Logger.new(IO::NULL)) }

  # referenced explicitly rather than via described_class, which resolves to the authenticator inside the nested group
  subject(:provider) { RubySMB::Gss::Provider::Multi.new([other_provider, ntlm_provider]) }

  describe '#initialize' do
    it 'requires at least one provider' do
      expect { RubySMB::Gss::Provider::Multi.new([]) }.to raise_error(ArgumentError)
      expect { RubySMB::Gss::Provider::Multi.new(nil) }.to raise_error(ArgumentError)
    end
  end

  describe '#mech_types' do
    it 'advertises every mechanism of every provider' do
      expect(provider.mech_types.map(&:oid)).to eq(
        [
          RubySMB::Gss::OID_KERBEROS_5.oid,
          RubySMB::Gss::OID_MICROSOFT_KERBEROS_5.oid,
          RubySMB::Gss::OID_NTLMSSP.oid
        ]
      )
    end

    it 'preserves the order the providers were given in' do
      reversed = RubySMB::Gss::Provider::Multi.new([ntlm_provider, other_provider])
      expect(reversed.mech_types.first.oid).to eq(RubySMB::Gss::OID_NTLMSSP.oid)
    end

    it 'advertises a mechanism supported by two providers only once' do
      duplicated = RubySMB::Gss::Provider::Multi.new([ntlm_provider, RubySMB::Gss::Provider::NTLM.new])
      expect(duplicated.mech_types.length).to eq(1)
    end
  end

  describe '#provider_for' do
    it 'finds the provider that handles the mechanism' do
      expect(provider.provider_for(RubySMB::Gss::OID_KERBEROS_5)).to be(other_provider)
      expect(provider.provider_for(RubySMB::Gss::OID_NTLMSSP)).to be(ntlm_provider)
    end

    it 'is nil when no provider handles the mechanism' do
      expect(provider.provider_for(RubySMB::Gss::OID_NEGOEX)).to be_nil
    end
  end

  describe RubySMB::Gss::Provider::Multi::Authenticator do
    subject(:authenticator) { provider.new_authenticator(server_client) }

    describe '#process' do
      context 'when building the advertisement' do
        it 'offers all of the mechanisms' do
          buffer = authenticator.process(nil).buffer
          expect(buffer).to eq(RubySMB::Gss.gss_neg_token_init(provider.mech_types))
        end

        it 'matches the underlying provider when only one is held' do
          single = described_class.new(RubySMB::Gss::Provider::Multi.new([ntlm_provider]), server_client)
          expect(single.process(nil).buffer).to eq(ntlm_provider.new_authenticator(server_client).process(nil).buffer)
        end

        it 'succeeds' do
          expect(authenticator.process(nil).nt_status).to eq(WindowsError::NTStatus::STATUS_SUCCESS)
        end
      end

      context 'when the client selects a mechanism' do
        it 'routes the token to the provider that handles it' do
          expect(other_authenticator).to receive(:process)
          authenticator.process(gss_init(RubySMB::Gss::OID_KERBEROS_5))
        end

        it 'routes an NTLM token to the NTLM provider' do
          type1 = Net::NTLM::Message::Type1.new.tap { |msg| msg.domain = domain }
          result = authenticator.process(RubySMB::Gss.gss_type1(type1.serialize))
          expect(result.nt_status).to eq(WindowsError::NTStatus::STATUS_MORE_PROCESSING_REQUIRED)
        end

        it 'refuses a mechanism no provider handles' do
          expect(authenticator.process(gss_init(RubySMB::Gss::OID_NEGOEX))).to be_nil
        end
      end

      context 'when the client continues an exchange' do
        it 'refuses a continuation before a mechanism has been selected' do
          # a NegTokenResp carries no mechanism OID, so there is nothing to route on
          expect(authenticator.process(RubySMB::Gss.gss_type3('anything'))).to be_nil
        end
      end

      it 'returns nil for a malformed request' do
        expect(authenticator.process('not asn1 at all')).to be_nil
      end
    end

    describe 'a complete NTLM exchange' do
      it 'authenticates the same as the NTLM provider on its own' do
        expect(complete_ntlm_exchange(authenticator)).to eq(
          complete_ntlm_exchange(ntlm_provider.new_authenticator(server_client))
        )
      end

      it 'succeeds for a known account' do
        status, identity = complete_ntlm_exchange(authenticator)
        expect(status).to eq(WindowsError::NTStatus::STATUS_SUCCESS)
        expect(identity).to eq("#{domain}\\#{username}")
      end

      it 'exposes the session key of the mechanism that authenticated' do
        complete_ntlm_exchange(authenticator)
        expect(authenticator.session_key).to_not be_nil
      end
    end

    describe '#reset!' do
      it 'forgets the selected mechanism' do
        complete_ntlm_exchange(authenticator)
        authenticator.reset!
        expect(authenticator.session_key).to be_nil
        # with no mechanism selected, a continuation token has nothing to route to
        expect(authenticator.process(RubySMB::Gss.gss_type3('anything'))).to be_nil
      end
    end
  end

  # Build a NegTokenInit that selects the specified mechanism, with an empty mechToken.
  def gss_init(mech_type)
    OpenSSL::ASN1::ASN1Data.new(
      [
        RubySMB::Gss::OID_SPNEGO,
        OpenSSL::ASN1::ASN1Data.new(
          [
            OpenSSL::ASN1::Sequence.new(
              [
                OpenSSL::ASN1::ASN1Data.new([OpenSSL::ASN1::Sequence.new([mech_type])], 0, :CONTEXT_SPECIFIC),
                OpenSSL::ASN1::ASN1Data.new([OpenSSL::ASN1::OctetString.new('')], 2, :CONTEXT_SPECIFIC)
              ]
            )
          ], 0, :CONTEXT_SPECIFIC
        )
      ], 0, :APPLICATION
    ).to_der
  end

  # Drive a full NTLM negotiation through the authenticator, returning the final status and identity.
  def complete_ntlm_exchange(authenticator)
    authenticator.process(nil)
    type1 = Net::NTLM::Message::Type1.new.tap { |msg| msg.domain = domain }
    challenge_result = authenticator.process(RubySMB::Gss.gss_type1(type1.serialize))
    raw_type2 = RubySMB::Gss.asn1dig(OpenSSL::ASN1.decode(challenge_result.buffer), 0, 2, 0).value
    type2 = Net::NTLM::Message.parse(raw_type2)
    type3 = type2.response({ user: username, password: password, domain: domain }, { ntlmv2: true })
    result = authenticator.process(RubySMB::Gss.gss_type3(type3.serialize))
    [result.nt_status, result.identity]
  end
end
