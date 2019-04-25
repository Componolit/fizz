with CPP;
with RFLX.Types;

package Extension_Parser with
  SPARK_Mode
is

   procedure Parse_Signature_Algorithms (Buffer :     RFLX.Types.Bytes;
                                         Result : out CPP.Signature_Algorithms_Record);

   procedure Parse_Supported_Groups (Buffer :     RFLX.Types.Bytes;
                                     Result : out CPP.Supported_Groups_Record);

end Extension_Parser;
