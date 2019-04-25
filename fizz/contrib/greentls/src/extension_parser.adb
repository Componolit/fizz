with CPP;
with RFLX.TLS_Handshake; use RFLX.TLS_Handshake;
with RFLX.TLS_Handshake.Signature_Algorithms;
with RFLX.TLS_Handshake.Signature_Schemes;
with RFLX.TLS_Handshake.Supported_Groups;
with RFLX.TLS_Handshake.Named_Groups;

package body Extension_Parser with
  SPARK_Mode
is

   procedure Parse_Signature_Algorithms (Buffer :     RFLX.Types.Bytes;
                                         Result : out CPP.Signature_Algorithms_Record)
   is
      First  : RFLX.Types.Length_Type;
      Last   : RFLX.Types.Length_Type;
      Cursor : RFLX.TLS_Handshake.Signature_Schemes.Cursor_Type;
      Index  : Natural := 1;
   begin
      Result := (Count => 0,
                 Algorithms => (others => 0));

      Signature_Algorithms.Label (Buffer);
      if Signature_Algorithms.Is_Valid (Buffer) then
         Signature_Algorithms.Get_Algorithms (Buffer, First, Last);
         Cursor := Signature_Schemes.First (Buffer (First .. Last));
         while Index <= Result.Algorithms'Last and then Signature_Schemes.Valid_Element (Buffer (First .. Last), Cursor) loop
            pragma Loop_Invariant (Index >= Result.Algorithms'First);
            Result.Algorithms (Index) := CPP.Uint16_T (Convert_To_Signature_Scheme_Base (Signature_Schemes.Get_Element (Buffer (First .. Last), Cursor)));
            Signature_Schemes.Next (Buffer (First .. Last), Cursor);
            Index := Index + 1;
         end loop;
         Result.Count := RFLX.Types.Byte (Index - 1);
      end if;
   end;

   procedure Parse_Supported_Groups (Buffer :     RFLX.Types.Bytes;
                                     Result : out CPP.Supported_Groups_Record)
   is
      First  : RFLX.Types.Length_Type;
      Last   : RFLX.Types.Length_Type;
      Cursor : RFLX.TLS_Handshake.Named_Groups.Cursor_Type;
      Index  : Natural := 1;
   begin
      Result := (Count => 0,
                 Groups => (others => 0));

      Supported_Groups.Label (Buffer);
      if Supported_Groups.Is_Valid (Buffer) then
         Supported_Groups.Get_Groups (Buffer, First, Last);
         Cursor := Named_Groups.First (Buffer (First .. Last));
         while Index <= Result.Groups'Last and then Named_Groups.Valid_Element (Buffer (First .. Last), Cursor) loop
            pragma Loop_Invariant (Index >= Result.Groups'First);
            Result.Groups (Index) := CPP.Uint16_T (Convert_To_Named_Group_Base (Named_Groups.Get_Element (Buffer (First .. Last), Cursor)));
            Named_Groups.Next (Buffer (First .. Last), Cursor);
            Index := Index + 1;
         end loop;
         Result.Count := RFLX.Types.Byte (Index - 1);
      end if;
   end;

end Extension_Parser;
