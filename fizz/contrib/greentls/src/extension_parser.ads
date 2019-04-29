with CPP;
with RFLX.Types;

package Extension_Parser with
  SPARK_Mode
is

   procedure Parse_Signature_Algorithms (Buffer :     RFLX.Types.Bytes;
                                         Result : out CPP.Signature_Algorithms_Record);

   procedure Parse_Supported_Groups (Buffer :     RFLX.Types.Bytes;
                                     Result : out CPP.Supported_Groups_Record);

   procedure Parse_Client_Key_Share (Buffer :     RFLX.Types.Bytes;
                                     Result : out CPP.Client_Key_Share_Record);

   procedure Parse_Server_Key_Share (Buffer :     RFLX.Types.Bytes;
                                     Result : out CPP.Server_Key_Share_Record);

   procedure Parse_Hello_Retry_Request_Key_Share (Buffer :     RFLX.Types.Bytes;
                                                  Result : out CPP.Hello_Retry_Request_Key_Share_Record);

   procedure Parse_Client_Preshared_Key (Buffer :     RFLX.Types.Bytes;
                                         Result : out CPP.Client_Preshared_Key_Record);

   procedure Parse_Server_Preshared_Key (Buffer :     RFLX.Types.Bytes;
                                         Result : out CPP.Server_Preshared_Key_Record);

   procedure Parse_Early_Data_Indication (Buffer :     RFLX.Types.Bytes;
                                          Result : out CPP.Early_Data_Indication_Record);

   procedure Parse_Cookie (Buffer :     RFLX.Types.Bytes;
                           Result : out CPP.Cookie_Record);

end Extension_Parser;
