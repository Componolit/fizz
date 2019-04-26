with CPP;
with RFLX.Types; use type RFLX.Types.Length_Type;
with RFLX.TLS_Handshake; use RFLX.TLS_Handshake;
with RFLX.TLS_Handshake.Signature_Algorithms;
with RFLX.TLS_Handshake.Signature_Schemes;
with RFLX.TLS_Handshake.Supported_Groups;
with RFLX.TLS_Handshake.Named_Groups;
with RFLX.TLS_Handshake.Key_Share_CH;
with RFLX.TLS_Handshake.Key_Share_SH;
with RFLX.TLS_Handshake.Key_Share_HRR;
with RFLX.TLS_Handshake.Key_Share_Entry;
with RFLX.TLS_Handshake.Key_Share_Entries;

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

   procedure Parse_Client_Key_Share (Buffer :     RFLX.Types.Bytes;
                                     Result : out CPP.Client_Key_Share_Record)
   is
      First  : RFLX.Types.Length_Type;
      Last   : RFLX.Types.Length_Type;
      Cursor : RFLX.TLS_Handshake.Key_Share_Entries.Cursor_Type;
      Index  : Natural := 1;
   begin
      Result := (Valid => CPP.Bool (False),
                 Count => 0,
                 Shares => (others => (0, 0, 0)));

      Key_Share_CH.Label (Buffer);
      if Key_Share_CH.Is_Valid (Buffer) then
         Key_Share_CH.Get_Shares (Buffer, First, Last);
         Cursor := Key_Share_Entries.First (Buffer (First .. Last));
         while Index <= Result.Shares'Last and then Key_Share_Entries.Valid_Element (Buffer (First .. Last), Cursor) loop
            declare
               Cf : constant RFLX.Types.Index_Type := Cursor.First;
               Cl : constant RFLX.Types.Index_Type := Cursor.Last;
            begin
               pragma Loop_Invariant (Index >= Result.Shares'First);
               pragma Loop_Invariant (Index <= Result.Shares'Last);
               pragma Loop_Invariant (Cf = Cursor.First and then Cl = Cursor.Last);
               pragma Loop_Invariant (Cf >= First and then Cl <= Last);
               pragma Loop_Invariant (Key_Share_Entry.Is_Contained (Buffer (Cf .. Cl)));
               pragma Loop_Invariant (Key_Share_Entry.Is_Valid (Buffer (Cf .. Cl)));
            end;

            Result.Shares (Index) := (Group => CPP.Uint16_T (Convert_To_Named_Group_Base (Key_Share_Entry.Get_Group (Buffer (Cursor.First .. Cursor.Last)))),
                                      Length => CPP.Uint16_T (Key_Share_Entry.Get_Length (Buffer (Cursor.First .. Cursor.Last))),
                                      Offset => CPP.Uint32_T (Key_Share_Entry.Get_Key_Exchange_First (Buffer (Cursor.First .. Cursor.Last)) - 1));
            Key_Share_Entries.Next (Buffer (First .. Last), Cursor);
            Index := Index + 1;
         end loop;
         Result.Count := RFLX.Types.Byte (Index - 1);
      end if;
      Result.Valid := CPP.Bool (True);
   end;

   procedure Parse_Server_Key_Share (Buffer :     RFLX.Types.Bytes;
                                     Result : out CPP.Server_Key_Share_Record)
   is
   begin
      Result := (Valid => CPP.Bool (False),
                 Share => (0, 0, 0));

      Key_Share_SH.Label (Buffer);
      if Key_Share_SH.Is_Valid (Buffer) then
         Result := (Valid => CPP.Bool (True),
                    Share => (Group => CPP.Uint16_T (Convert_To_Named_Group_Base (Key_Share_SH.Get_Group (Buffer))),
                              Length => CPP.Uint16_T (Key_Share_SH.Get_Length (Buffer)),
                              Offset => CPP.Uint32_T (Key_Share_SH.Get_Key_Exchange_First (Buffer) - 1)));
      end if;
   end;

   procedure Parse_Hello_Retry_Request_Key_Share (Buffer :     RFLX.Types.Bytes;
                                                  Result : out CPP.Hello_Retry_Request_Key_Share_Record)
   is
   begin
      Result := (Valid => CPP.Bool (False),
                 Selected_Group => 0);

      Key_Share_HRR.Label (Buffer);
      if Key_Share_HRR.Is_Valid (Buffer) then
         Result := (Valid => CPP.Bool (True),
                    Selected_Group => CPP.Uint16_T (Convert_To_Named_Group_Base (Key_Share_HRR.Get_Selected_Group (Buffer))));
      end if;
   end;

end Extension_Parser;
