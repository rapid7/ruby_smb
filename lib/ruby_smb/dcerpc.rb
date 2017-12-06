module RubySMB
  # DCERPC PDU's
  # http://pubs.opengroup.org/onlinepubs/9629399/
  module Dcerpc
    require 'ruby_smb/dcerpc/uuid'
    require 'ruby_smb/dcerpc/request'
    require 'ruby_smb/dcerpc/response'
    require 'ruby_smb/dcerpc/handle'
    require 'ruby_smb/dcerpc/srvsvc'
    require 'ruby_smb/dcerpc/bind'
  end
end