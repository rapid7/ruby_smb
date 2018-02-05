module RubySMB
  module Nbss
    # Representation of the NetBIOS Session Service Request packet as defined in
    # [4.3.2 SESSION REQUEST PACKET](https://tools.ietf.org/html/rfc1002)
    class SessionRequest < BinData::Record
      endian :big

      session_header :session_header
      string         :called_name,  label: 'Called Name'
      string         :calling_name, label: 'Calling Name'
    end
  end
end
