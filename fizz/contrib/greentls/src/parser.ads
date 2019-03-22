with Interfaces.C;

with CPP;
with RFLX.Types;
with RFLX.TLS_Handshake; use RFLX.TLS_Handshake;

package Parser
  with SPARK_Mode
is

   procedure Parse_Handshake_Message (Buffer :     RFLX.Types.Bytes;
                                      Result : out CPP.Handshake_Record);

   procedure Parse_Alert_Message (Buffer :     RFLX.Types.Bytes;
                                  Result : out CPP.Alert_Record);

end Parser;
