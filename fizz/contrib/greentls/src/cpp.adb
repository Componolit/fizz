with Parser;
with Extension_Parser;
with RFLX.Types; use type RFLX.Types.Length_Type;
with RFLX.TLS_Handshake.Handshake;

package body CPP is

   procedure Parse_Handshake_Message (Buffer_Address : System.Address; Buffer_Length : Interfaces.C.Size_T; Result_Address : in out System.Address)
   is
      Buffer : RFLX.Types.Bytes (RFLX.Types.Index_Type'First .. RFLX.Types.Index_Type'First + RFLX.Types.Length_Type (Buffer_Length) - 1) with
        Address => Buffer_Address;
      Result : CPP.Handshake_Record with
        Address => Result_Address;
   begin
      Parser.Parse_Handshake_Message (Buffer, Result);
   end Parse_Handshake_Message;

   procedure Parse_Alert_Message (Buffer_Address :        System.Address;
                                  Buffer_Length  :        Interfaces.C.Size_T;
                                  Result_Address : in out System.Address)
   is
      Buffer : RFLX.Types.Bytes (RFLX.Types.Index_Type'First .. RFLX.Types.Index_Type'First
                                 + RFLX.Types.Length_Type (Buffer_Length) - 1) with
        Address => Buffer_Address;
      Result : CPP.Alert_Record with
        Address => Result_Address;
   begin
      Parser.Parse_Alert_Message (Buffer, Result);
   end Parse_Alert_Message;

   procedure Parse_Signature_Algorithms (Buffer_Address :        System.Address;
                                         Buffer_Length  :        Interfaces.C.Size_T;
                                         Result_Address : in out System.Address)
   is
      Buffer : RFLX.Types.Bytes (RFLX.Types.Index_Type'First .. RFLX.Types.Index_Type'First
                                 + RFLX.Types.Length_Type (Buffer_Length) - 1) with
        Address => Buffer_Address;
      Result : CPP.Signature_Algorithms_Record with
        Address => Result_Address;
   begin
      Extension_Parser.Parse_Signature_Algorithms (Buffer, Result);
   end Parse_Signature_Algorithms;

   procedure Parse_Supported_Groups (Buffer_Address :        System.Address;
                                     Buffer_Length  :        Interfaces.C.Size_T;
                                     Result_Address : in out System.Address)
   is
      Buffer : RFLX.Types.Bytes (RFLX.Types.Index_Type'First .. RFLX.Types.Index_Type'First
                                 + RFLX.Types.Length_Type (Buffer_Length) - 1) with
        Address => Buffer_Address;
      Result : CPP.Supported_Groups_Record with
        Address => Result_Address;
   begin
      Extension_Parser.Parse_Supported_Groups (Buffer, Result);
   end Parse_Supported_Groups;

   procedure Parse_Client_Key_Share (Buffer_Address :        System.Address;
                                     Buffer_Length  :        Interfaces.C.Size_T;
                                     Result_Address : in out System.Address)
   is
      Buffer : RFLX.Types.Bytes (RFLX.Types.Index_Type'First .. RFLX.Types.Index_Type'First
                                 + RFLX.Types.Length_Type (Buffer_Length) - 1) with
        Address => Buffer_Address;
      Result : CPP.Client_Key_Share_Record with
        Address => Result_Address;
   begin
      Extension_Parser.Parse_Client_Key_Share (Buffer, Result);
   end Parse_Client_Key_Share;

   procedure Parse_Server_Key_Share (Buffer_Address :        System.Address;
                                     Buffer_Length  :        Interfaces.C.Size_T;
                                     Result_Address : in out System.Address)
   is
      Buffer : RFLX.Types.Bytes (RFLX.Types.Index_Type'First .. RFLX.Types.Index_Type'First
                                 + RFLX.Types.Length_Type (Buffer_Length) - 1) with
        Address => Buffer_Address;
      Result : CPP.Server_Key_Share_Record with
        Address => Result_Address;
   begin
      Extension_Parser.Parse_Server_Key_Share (Buffer, Result);
   end Parse_Server_Key_Share;

   procedure Parse_Hello_Retry_Request_Key_Share (Buffer_Address :        System.Address;
                                                  Buffer_Length  :        Interfaces.C.Size_T;
                                                  Result_Address : in out System.Address)
   is
      Buffer : RFLX.Types.Bytes (RFLX.Types.Index_Type'First .. RFLX.Types.Index_Type'First
                                 + RFLX.Types.Length_Type (Buffer_Length) - 1) with
        Address => Buffer_Address;
      Result : CPP.Hello_Retry_Request_Key_Share_Record with
        Address => Result_Address;
   begin
      Extension_Parser.Parse_Hello_Retry_Request_Key_Share (Buffer, Result);
   end Parse_Hello_Retry_Request_Key_Share;

   procedure Parse_Client_Preshared_Key (Buffer_Address :        System.Address;
                                     Buffer_Length  :        Interfaces.C.Size_T;
                                     Result_Address : in out System.Address)
   is
      Buffer : RFLX.Types.Bytes (RFLX.Types.Index_Type'First .. RFLX.Types.Index_Type'First
                                 + RFLX.Types.Length_Type (Buffer_Length) - 1) with
        Address => Buffer_Address;
      Result : CPP.Client_Preshared_Key_Record with
        Address => Result_Address;
   begin
      Extension_Parser.Parse_Client_Preshared_Key (Buffer, Result);
   end Parse_Client_Preshared_Key;

   procedure Parse_Server_Preshared_Key (Buffer_Address :        System.Address;
                                         Buffer_Length  :        Interfaces.C.Size_T;
                                         Result_Address : in out System.Address)
   is
      Buffer : RFLX.Types.Bytes (RFLX.Types.Index_Type'First .. RFLX.Types.Index_Type'First
                                 + RFLX.Types.Length_Type (Buffer_Length) - 1) with
        Address => Buffer_Address;
      Result : CPP.Server_Preshared_Key_Record with
        Address => Result_Address;
   begin
      Extension_Parser.Parse_Server_Preshared_Key (Buffer, Result);
   end Parse_Server_Preshared_Key;

   procedure Parse_Early_Data_Indication (Buffer_Address :        System.Address;
                                         Buffer_Length  :        Interfaces.C.Size_T;
                                         Result_Address : in out System.Address)
   is
      Buffer : RFLX.Types.Bytes (RFLX.Types.Index_Type'First .. RFLX.Types.Index_Type'First
                                 + RFLX.Types.Length_Type (Buffer_Length) - 1) with
        Address => Buffer_Address;
      Result : CPP.Early_Data_Indication_Record with
        Address => Result_Address;
   begin
      Extension_Parser.Parse_Early_Data_Indication (Buffer, Result);
   end Parse_Early_Data_Indication;

end CPP;
