with Interfaces.C;
with Interfaces.C.Extensions;
with System;

with RFLX.Types;

package CPP with
  SPARK_Mode
is
   subtype Bool is Interfaces.C.Extensions.Bool;
   type Bool_Array is array (Natural range <>) of Bool;
   subtype Unsigned_Char is Interfaces.C.Unsigned_Char;
   type Unsigned_Char_Array is array (Natural range <>) of Unsigned_Char;
   subtype Unsigned_Short is Interfaces.C.Unsigned_Short;
   type Unsigned_Short_Array is array (Natural range <>) of Unsigned_Short;
   subtype Unsigned_Int is Interfaces.C.Unsigned;
   type Unsigned_Int_Array is array (Natural range <>) of Unsigned_Int;
   subtype Unsigned_Long is Interfaces.C.Unsigned_Long;
   type Unsigned_Long_Array is array (Natural range <>) of Unsigned_Long;
   subtype Unsigned_Long_Long is Interfaces.C.Extensions.Unsigned_Long_Long;
   type Unsigned_Long_Long_Array is array (Natural range <>) of Unsigned_Long_Long;
   subtype Char is Interfaces.C.Char;
   type Char_Array is array (Natural range <>) of Char;
   subtype Signed_Char is Interfaces.C.Signed_Char;
   type Signed_Char_Array is array (Natural range <>) of Signed_Char;
   subtype Wchar_T is Interfaces.C.Wchar_T;
   type Wchar_T_Array is array (Natural range <>) of Wchar_T;
   subtype Short is Interfaces.C.Short;
   type Short_Array is array (Natural range <>) of Short;
   subtype Int is Interfaces.C.Int;
   type Int_Array is array (Natural range <>) of Int;
   subtype C_X_Int128 is Interfaces.C.Extensions.Signed_128;
   type C_X_Int128_Array is array (Natural range <>) of C_X_Int128;
   subtype Long is Interfaces.C.Long;
   type Long_Array is array (Natural range <>) of Long;
   subtype Long_Long is Interfaces.C.Extensions.Long_Long;
   type Long_Long_Array is array (Natural range <>) of Long_Long;
   subtype C_Float is Interfaces.C.C_Float;
   type C_Float_Array is array (Natural range <>) of C_Float;
   subtype Double is Interfaces.C.Double;
   type Double_Array is array (Natural range <>) of Double;
   subtype Void is Interfaces.C.Extensions.Void;
   type Void_Array is array (Natural range <>) of Void;
   subtype Void_Address is Interfaces.C.Extensions.Void_Ptr;
   type Void_Address_Array is array (Natural range <>) of Void_Address;

   subtype Int8_T is CPP.Signed_Char;
   subtype Int8_T_Array is CPP.Signed_Char_Array;
   subtype Int16_T is CPP.Short;
   subtype Int16_T_Array is CPP.Short_Array;
   subtype Int32_T is CPP.Int;
   subtype Int32_T_Array is CPP.Int_Array;
   subtype Int64_T is CPP.Long;
   subtype Int64_T_Array is CPP.Long_Array;
   subtype Uint8_T is RFLX.Types.Byte;
   subtype Uint8_T_Array is RFLX.Types.Bytes;
   subtype Uint16_T is CPP.Unsigned_Short;
   subtype Uint16_T_Array is CPP.Unsigned_Short_Array;
   subtype Uint32_T is CPP.Unsigned_Int;
   subtype Uint32_T_Array is CPP.Unsigned_Int_Array;
   subtype Uint64_T is CPP.Unsigned_Long;
   subtype Uint64_T_Array is CPP.Unsigned_Long_Array;
   subtype Intptr_T is CPP.Long;
   subtype Intptr_T_Array is CPP.Long_Array;
   subtype Uintptr_T is CPP.Unsigned_Long;
   subtype Uintptr_T_Array is CPP.Unsigned_Long_Array;
   subtype Intmax_T is CPP.Long;
   subtype Intmax_T_Array is CPP.Long_Array;
   subtype Uintmax_T is CPP.Unsigned_Long;
   subtype Uintmax_T_Array is CPP.Unsigned_Long_Array;

   type Extension_Record is
      record
         Tag    : Uint16_T;
         Length : Uint16_T;
         Offset : Uint32_T;
      end record
     with
       Convention => C;

   type Extension_Record_Array is array (Natural range <>) of Extension_Record;

   type Client_Hello_Record is
      record
         Random                   : Uint8_T_Array (1 .. 32);
         Legacy_Session_Id_Length : Uint8_T;
         Legacy_Session_Id        : Uint8_T_Array (1 .. 256);
         Cipher_Suites_Count      : Uint8_T;
         Cipher_Suites            : Uint16_T_Array (1 .. 4);
         Extensions_Count         : Uint8_T;
         Extensions               : Extension_Record_Array (1 .. 8);
      end record
     with
       Convention => C;

   type Server_Hello_Record is
      record
         Random                   : Uint8_T_Array (1 .. 32);
         Legacy_Session_Id_Length : Uint8_T;
         Legacy_Session_Id        : Uint8_T_Array (1 .. 256);
         Cipher_Suite             : Uint16_T;
         Extensions_Count         : Uint8_T;
         Extensions               : Extension_Record_Array (1 .. 8);
      end record
     with
       Convention => C;

   type Encrypted_Extensions_Record is
      record
         Extensions_Count : Uint8_T;
         Extensions       : Extension_Record_Array (1 .. 8);
      end record
     with
       Convention => C;

   type Certificate_Entry_Record is
      record
         Certificate_Entry_Length : Uint32_T;
         Certificate_Entry_Offset : Uint32_T;
         Extensions_Count         : Uint8_T;
         Extensions               : Extension_Record_Array (1 .. 8);
      end record
     with
       Convention => C;

   type Certificate_Entry_Record_Array is array (Natural range <>) of Certificate_Entry_Record;

   type Certificate_Record is
      record
         Certificate_Request_Context_Length : Uint32_T;
         Certificate_Request_Context_Offset : Uint32_T;
         Certificates_Count                 : Uint8_T;
         Certificates                       : Certificate_Entry_Record_Array (1 .. 8);
      end record
     with
       Convention => C;

   type Certificate_Request_Record is
      record
         Certificate_Request_Context_Length : Uint32_T;
         Certificate_Request_Context_Offset : Uint32_T;
         Extensions_Count                   : Uint8_T;
         Extensions                         : Extension_Record_Array (1 .. 8);
      end record
     with
       Convention => C;

   type Certificate_Verify_Record is
      record
         Signature_Scheme : Uint16_T;
         Signature_Length : Uint32_T;
         Signature_Offset : Uint32_T;
      end record
     with
       Convention => C;

   type Finished_Record is
      record
         Verify_Data_Length : Uint32_T;
         Verify_Data_Offset : Uint32_T;
      end record
     with
       Convention => C;

   type New_Session_Ticket_Record is
      record
         Ticket_Lifetime     : Uint32_T;
         Ticket_Age_Add      : Uint32_T;
         Ticket_Nonce_Length : Uint32_T;
         Ticket_Nonce_Offset : Uint32_T;
         Ticket_Length       : Uint32_T;
         Ticket_Offset       : Uint32_T;
         Extensions_Count    : Uint8_T;
         Extensions          : Extension_Record_Array (1 .. 8);
      end record
     with
       Convention => C;

   type Key_Update_Record is
      record
         Request_Update : Uint8_T;
      end record
     with
       Convention => C;

   type Handshake_Variants (Tag : Uint8_T := 0) is
      record
         case Tag is
            when 1 =>
               Client_Hello         : Client_Hello_Record;
            when 2 =>
               Server_Hello         : Server_Hello_Record;
            when 4 =>
               New_Session_Ticket   : New_Session_Ticket_Record;
            when 8 =>
               Encrypted_Extensions : Encrypted_Extensions_Record;
            when 11 =>
               Certificate          : Certificate_Record;
            when 13 =>
               Certificate_Request  : Certificate_Request_Record;
            when 15 =>
               Certificate_Verify   : Certificate_Verify_Record;
            when 20 =>
               Finished             : Finished_Record;
            when 24 =>
               Key_Update           : Key_Update_Record;
            when others =>
               null;
         end case;
      end record;
   pragma Unchecked_Union (Handshake_Variants);

   type Handshake_Record is
      record
         Tag          : Uint8_T;
         Content      : Handshake_Variants;
      end record
     with
       Convention => C;

   type Alert_Record is
      record
         Level       : Uint8_T;
         Description : Uint8_T;
      end record
     with
       Convention => C;

   procedure Parse_Handshake_Message (Buffer_Address :        System.Address;
                                      Buffer_Length  :        Interfaces.C.Size_T;
                                      Result_Address : in out System.Address) with
     Global => null,
     Export => True,
     Convention => C,
     External_Name => "parseHandshakeMessage";

   procedure Parse_Alert_Message (Buffer_Address :        System.Address;
                                  Buffer_Length  :        Interfaces.C.Size_T;
                                  Result_Address : in out System.Address) with
     Global => null,
     Export => True,
     Convention => C,
     External_Name => "parseAlertMessage";

   type Signature_Algorithms_Record is
      record
         Count      : Uint8_T;
         Algorithms : Uint16_T_Array (1 .. 16);
      end record
     with
       Convention => C;

   type Supported_Groups_Record is
      record
         Count  : Uint8_T;
         Groups : Uint16_T_Array (1 .. 16);
      end record
     with
       Convention => C;

   type Key_Share_Entry_Record is
      record
         Group  : Uint16_T;
         Length : Uint16_T;
         Offset : Uint32_T;
      end record
     with
       Convention => C;

   type Key_Share_Entry_Record_Array is array (Natural range <>) of Key_Share_Entry_Record;

   type Client_Key_Share_Record is
      record
         Valid  : Bool;
         Count  : Uint8_T;
         Shares : Key_Share_Entry_Record_Array (1 .. 16);
      end record
     with
       Convention => C;

   type Server_Key_Share_Record is
      record
         Valid : Bool;
         Share : Key_Share_Entry_Record;
      end record
     with
       Convention => C;

   type Hello_Retry_Request_Key_Share_Record is
      record
         Valid          : Bool;
         Selected_Group : Uint16_T;
      end record
     with
       Convention => C;

   procedure Parse_Signature_Algorithms (Buffer_Address :        System.Address;
                                         Buffer_Length  :        Interfaces.C.Size_T;
                                         Result_Address : in out System.Address) with
     Global => null,
     Export => True,
     Convention => C,
     External_Name => "parseSignatureAlgorithms";

   procedure Parse_Supported_Groups (Buffer_Address :        System.Address;
                                     Buffer_Length  :        Interfaces.C.Size_T;
                                     Result_Address : in out System.Address) with
     Global => null,
     Export => True,
     Convention => C,
     External_Name => "parseSupportedGroups";

   procedure Parse_Client_Key_Share (Buffer_Address :        System.Address;
                                     Buffer_Length  :        Interfaces.C.Size_T;
                                     Result_Address : in out System.Address) with
     Global => null,
     Export => True,
     Convention => C,
     External_Name => "parseClientKeyShare";

   procedure Parse_Server_Key_Share (Buffer_Address :        System.Address;
                                     Buffer_Length  :        Interfaces.C.Size_T;
                                     Result_Address : in out System.Address) with
     Global => null,
     Export => True,
     Convention => C,
     External_Name => "parseServerKeyShare";

   procedure Parse_Hello_Retry_Request_Key_Share (Buffer_Address :        System.Address;
                                                  Buffer_Length  :        Interfaces.C.Size_T;
                                                  Result_Address : in out System.Address) with
     Global => null,
     Export => True,
     Convention => C,
     External_Name => "parseHelloRetryRequestKeyShare";

end CPP;
