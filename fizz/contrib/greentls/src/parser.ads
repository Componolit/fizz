with Interfaces.C;

with CPP;
with RFLX.Message_Sequence;
with RFLX.Types;
with RFLX.TLS_Handshake; use RFLX.TLS_Handshake;
with RFLX.TLS_Handshake.Generic_Extension;

package Parser
  with SPARK_Mode
is

   procedure Parse_Record_Message (Buffer :     RFLX.Types.Bytes;
                                   Result : out CPP.Record_Record);

   procedure Parse_Handshake_Message (Buffer :     RFLX.Types.Bytes;
                                      Result : out CPP.Handshake_Record);

   procedure Parse_Alert_Message (Buffer :     RFLX.Types.Bytes;
                                  Result : out CPP.Alert_Record);

private

   generic
      with package Extension is new RFLX.TLS_Handshake.Generic_Extension (<>);
      with package Extensions is new RFLX.Message_Sequence (<>);
   procedure Parse_Extensions (Buffer :        RFLX.Types.Bytes;
                               Count  :    out CPP.Uint8_T;
                               Result : in out CPP.Extension_Record_Array) with
     Pre => Extensions.Is_Contained (Buffer)
            and then Result'Length > 0
            and then Result'Length < 256;

end Parser;
