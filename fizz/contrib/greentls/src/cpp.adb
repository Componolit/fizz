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

end CPP;
