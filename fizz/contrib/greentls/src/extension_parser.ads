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

   procedure Parse_Supported_Versions (Buffer :     RFLX.Types.Bytes;
                                       Result : out CPP.Supported_Versions_Record);

   procedure Parse_Supported_Version (Buffer :     RFLX.Types.Bytes;
                                      Result : out CPP.Supported_Version_Record);

   procedure Parse_PSK_Key_Exchange_Modes (Buffer :     RFLX.Types.Bytes;
                                           Result : out CPP.PSK_Key_Exchange_Modes_Record);

   procedure Parse_Protocol_Name_List (Buffer :     RFLX.Types.Bytes;
                                       Result : out CPP.Protocol_Name_List_Record);

   procedure Parse_Server_Name_List (Buffer :     RFLX.Types.Bytes;
                                     Result : out CPP.Server_Name_List_Record);

end Extension_Parser;
