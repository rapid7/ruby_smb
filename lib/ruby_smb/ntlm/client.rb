module RubySMB::NTLM
  class Client < Net::NTLM::Client
    # There was a bunch of code in here that was necessary in versions up to and including rubyntlm version 0.6.3.
    # The class is kept because there are references to it that should be kept in place in case future alterations to
    # rubyntlm are required.
  end
end
