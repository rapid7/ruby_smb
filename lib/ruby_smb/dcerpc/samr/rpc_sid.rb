module RubySMB
  module Dcerpc
    module Samr
      WELL_KNOWN_SID_NAME = {
        [0,0] => 'NULL SID',
        [1,0] => 'Everyone',
        [2,0] => 'LOCAL',
        [2,1] => 'CONSOLE LOGON',
        [3,0] => 'CREATOR OWNER',
        [3,1] => 'CREATOR GROUP',
        [3,2] => 'CREATOR OWNER SERVER',
        [3,3] => 'CREATOR GROUP SERVER',
        [3,4] => 'OWNER RIGHTS',
        [5,1] => 'NT AUTHORITY\\DIALUP',
        [5,2] => 'NT AUTHORITY\\NETWORK',
        [5,3] => 'NT AUTHORITY\\BATCH',
        [5,4] => 'NT AUTHORITY\\INTERACTIVE',
        [5,6] => 'NT AUTHORITY\\SERVICE',
        [5,7] => 'NT AUTHORITY\\ANONYMOUS LOGON',
        [5,8] => 'NT AUTHORITY\\PROXY',
        [5,9] => 'NT AUTHORITY\\ENTERPRISE DOMAIN CONTROLLERS',
        [5,10] => 'NT AUTHORITY\\SELF',
        [5,11] => 'NT AUTHORITY\\Authenticated Users',
        [5,12] => 'NT AUTHORITY\\RESTRICTED',
        [5,13] => 'NT AUTHORITY\\TERMINAL SERVER USER',
        [5,14] => 'NT AUTHORITY\\REMOTE INTERACTIVE LOGON',
        [5,15] => 'NT AUTHORITY\\This Organization',
        [5,17] => 'NT AUTHORITY\\IUSR',
        [5,18] => 'NT AUTHORITY\\SYSTEM',
        [5,19] => 'NT AUTHORITY\\LOCAL SERVICE',
        [5,20] => 'NT AUTHORITY\\NETWORK SERVICE',
        [5,22] => 'NT AUTHORITY\\ENTERPRISE READ-ONLY DOMAIN CONTROLLERS BETA',
        [5,33] => 'NT AUTHORITY\\WRITE RESTRICTED',
        [5,32] => 'Builtin Domain'
      }

      WELL_KNOWN_RID_NAME = {
        498 => '(domain)\\Enterprise Read-only Domain Controllers',
        500 => '(domain)\\Administrator',
        501 => '(domain)\\Guest',
        502 => '(domain)\\krbtgt',
        512 => '(domain)\\Domain Admins',
        513 => '(domain)\\Domain Users',
        514 => '(domain)\\Domain Guests',
        515 => '(domain)\\Domain Computers',
        516 => '(domain)\\Domain Controllers',
        517 => '(domain)\\Cert Publishers',
        518 => '(domain)\\Schema Admins',
        519 => '(domain)\\Enterprise Admins',
        520 => '(domain)\\Group Policy Creator Owners',
        521 => '(domain)\\Read-only Domain Controllers',
        522 => '(domain)\\Cloneable Domain Controllers',
        544 => 'BUILTIN\\Administrators',
        545 => 'BUILTIN\\Users',
        546 => 'BUILTIN\\Guests',
        548 => 'BUILTIN\\Account Operators',
        549 => 'BUILTIN\\Server Operators',
        550 => 'BUILTIN\\Print Operators',
        551 => 'BUILTIN\\Backup Operators',
        552 => 'BUILTIN\\Replicator',
        553 => '(domain)\\RAS and IAS Servers',
        554 => 'BUILTIN\\Pre-Windows 2000 Compatible Access',
        555 => 'BUILTIN\\Remote Desktop Users',
        556 => 'BUILTIN\\Network Configuration Operators',
        557 => 'BUILTIN\\Incoming Forest Trust Builders',
        558 => 'BUILTIN\\Performance Monitor Users',
        559 => 'BUILTIN\\Performance Log Users',
        560 => 'BUILTIN\\Windows Authorization Access Group',
        561 => 'BUILTIN\\Terminal Server License Servers',
        562 => 'BUILTIN\\Distributed COM Users',
        568 => 'BUILTIN\\IIS_IUSRS',
        569 => 'BUILTIN\\Cryptographic Operators',
        571 => '(domain)\\Allowed RODC Password Replication Group',
        572 => '(domain)\\Denied RODC Password Replication Group',
        573 => 'BUILTIN\\Event Log Readers',
        574 => 'BUILTIN\\Certificate Service DCOM Access',
        575 => 'BUILTIN\\RDS Remote Access Servers',
        576 => 'BUILTIN\\RDS Endpoint Servers',
        577 => 'BUILTIN\\RDS Management Servers',
        578 => 'BUILTIN\\Hyper-V Administrators',
        579 => 'BUILTIN\\Access Control Assistance Operators',
        580 => 'BUILTIN\\Remote Management Users'
      }

      #[2.4.1.1 RPC_SID_IDENTIFIER_AUTHORITY](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/d7e6e5a5-437c-41e5-8ba1-bdfd43e96cbc)
      class RpcSidIdentifierAuthority < Ndr::NdrFixArray
        default_parameters type: :ndr_uint8, initial_length: 6, byte_align: 1
      end

      # [2.4.2.3 RPC_SID](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/5cb97814-a1c2-4215-b7dc-76d1f4bfad01)
      class RpcSid < Ndr::NdrStruct
        default_parameters byte_align: 4
        endian :little

        ndr_uint8                    :revision
        ndr_uint8                    :sub_authority_count, initial_value: -> { self.sub_authority.size }
        rpc_sid_identifier_authority :identifier_authority
        ndr_conf_array               :sub_authority, type: :ndr_uint32

        def snapshot
          sid = ['S', self.revision.to_s, self.identifier_authority[-1].to_s]
          self.sub_authority.each { |e| sid << e.to_s }
          sid.join('-')
        end

        def assign(val)
          case val
          when String
            elems = val.split('-')
            raise ArgumentError, "Wrong SID format for #{val.inspect}" unless elems[0].downcase == 's'
            self.revision = elems[1].to_i
            self.sub_authority_count = elems[3..-1].size
            self.identifier_authority = [0, 0, 0, 0, 0, elems[2].to_i]
            self.sub_authority = elems[3..-1].map(&:to_i)
          when RpcSid
            super
          else
            raise ArgumentError, "Can only assign String or other RpcSid object (got #{val.class})"
          end
          self
        end

        def name
          sid = case sub_authority.size
          when 1
            WELL_KNOWN_SID_NAME[[identifier_authority[-1].to_i, sub_authority[0].to_i]]
          when 2
            if identifier_authority[-1] == 5 && sub_authority[0] == 32
              WELL_KNOWN_RID_NAME[sub_authority[1]]
            end
          when 3
            if identifier_authority[-1] == 5 && sub_authority[0] == 5
              "Current Session Logon SID"
            end
          else
            if identifier_authority[-1] == 5
              WELL_KNOWN_RID_NAME[sub_authority.last]
            end
          end
          sid || "Unknown SID (#{self})"
        end
      end

      class PrpcSid < RpcSid
        extend Ndr::PointerClassPlugin
      end

    end
  end
end
