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
with RFLX.TLS_Handshake.Pre_Shared_Key_CH;
with RFLX.TLS_Handshake.Pre_Shared_Key_SH;
with RFLX.TLS_Handshake.PSK_Identity;
with RFLX.TLS_Handshake.PSK_Identities;
with RFLX.TLS_Handshake.PSK_Binder_Entry;
with RFLX.TLS_Handshake.PSK_Binder_Entries;

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

   procedure Parse_Client_Preshared_Key (Buffer :     RFLX.Types.Bytes;
                                         Result : out CPP.Client_Preshared_Key_Record)
   is
      First           : RFLX.Types.Length_Type;
      Last            : RFLX.Types.Length_Type;
      Identity_Cursor : RFLX.TLS_Handshake.PSK_Identities.Cursor_Type;
      Identity_Index  : Natural := 1;
      Binder_Cursor   : RFLX.TLS_Handshake.PSK_Binder_Entries.Cursor_Type;
      Binder_Index    : Natural := 1;
   begin
      Result := (Valid => CPP.Bool (False),
                 Identity_Count => 0,
                 Identities => (others => (0, 0, 0)),
                 Binder_Count => 0,
                 Binders => (others => (0, 0)));

      Pre_Shared_Key_CH.Label (Buffer);
      if Pre_Shared_Key_CH.Is_Valid (Buffer) then
         Pre_Shared_Key_CH.Get_Identities (Buffer, First, Last);
         Identity_Cursor := PSK_Identities.First (Buffer (First .. Last));
         pragma Assert (Identity_Cursor.First >= First);
         pragma Assert (Identity_Cursor.Last <= Last);
         pragma Assert (PSK_Identity.Is_Contained (Buffer (Identity_Cursor.First .. Identity_Cursor.Last)));
         while Identity_Index <= Result.Identities'Last and then PSK_Identities.Valid_Element (Buffer (First .. Last), Identity_Cursor) loop
            declare
               Cf : constant RFLX.Types.Index_Type := Identity_Cursor.First;
               Cl : constant RFLX.Types.Index_Type := Identity_Cursor.Last;
            begin
               pragma Loop_Invariant (Identity_Index >= Result.Identities'First);
               pragma Loop_Invariant (Identity_Index <= Result.Identities'Last);
               pragma Loop_Invariant (Cf = Identity_Cursor.First and then Cl = Identity_Cursor.Last);
               pragma Loop_Invariant (Cf >= First and then Cl <= Last);
               pragma Loop_Invariant (PSK_Identity.Is_Contained (Buffer (Cf .. Cl)));
               pragma Loop_Invariant (PSK_Identity.Is_Valid (Buffer (Cf .. Cl)));
            end;
            Result.Identities (Identity_Index) := (Identity_Length => CPP.Uint16_T (PSK_Identity.Get_Length (Buffer (Identity_Cursor.First .. Identity_Cursor.Last))),
                                                   Identity_Offset => CPP.Uint32_T (PSK_Identity.Get_Identity_First (Buffer (Identity_Cursor.First .. Identity_Cursor.Last)) - 1),
                                                   Obfuscated_Ticket_Age => CPP.Uint32_T (PSK_Identity.Get_Obfuscated_Ticket_Age (Buffer (Identity_Cursor.First .. Identity_Cursor.Last))));
            PSK_Identities.Next (Buffer (First .. Last), Identity_Cursor);
            Identity_Index := Identity_Index + 1;
         end loop;
         Result.Identity_Count := CPP.Uint8_T (Identity_Index - 1);

         Pre_Shared_Key_CH.Get_Binders (Buffer, First, Last);
         Binder_Cursor := PSK_Binder_Entries.First (Buffer (First .. Last));
         while Binder_Index <= Result.Binders'Last and then PSK_Binder_Entries.Valid_Element (Buffer (First .. Last), Binder_Cursor) loop
            declare
               Cf : constant RFLX.Types.Index_Type := Binder_Cursor.First;
               Cl : constant RFLX.Types.Index_Type := Binder_Cursor.Last;
            begin
               pragma Loop_Invariant (Binder_Index >= Result.Binders'First);
               pragma Loop_Invariant (Binder_Index <= Result.Binders'Last);
               pragma Loop_Invariant (Cf = Binder_Cursor.First and then Cl = Binder_Cursor.Last);
               pragma Loop_Invariant (Cf >= First and then Cl <= Last);
               pragma Loop_Invariant (PSK_Binder_Entry.Is_Contained (Buffer (Cf .. Cl)));
               pragma Loop_Invariant (PSK_Binder_Entry.Is_Valid (Buffer (Cf .. Cl)));
            end;
            Result.Binders (Binder_Index) := (Binder_Length => CPP.Uint16_T (PSK_Binder_Entry.Get_Length (Buffer (Binder_Cursor.First .. Binder_Cursor.Last))),
                                              Binder_Offset => CPP.Uint32_T (PSK_Binder_Entry.Get_PSK_Binder_Entry_First (Buffer (Binder_Cursor.First .. Binder_Cursor.Last)) - 1));
            PSK_Binder_Entries.Next (Buffer (First .. Last), Binder_Cursor);
            Binder_Index := Binder_Index + 1;
         end loop;
         Result.Binder_Count := CPP.Uint8_T (Binder_Index - 1);

         Result.Valid := CPP.Bool (True);
      end if;
   end;

   procedure Parse_Server_Preshared_Key (Buffer :     RFLX.Types.Bytes;
                                         Result : out CPP.Server_Preshared_Key_Record)
   is
   begin
      Result := (Valid => CPP.Bool (False),
                 Selected_Identity => 0);

      Pre_Shared_Key_SH.Label (Buffer);
      if Pre_Shared_Key_SH.Is_Valid (Buffer) then
         Result := (Valid => CPP.Bool (True),
                    Selected_Identity => CPP.Uint16_T (Pre_Shared_Key_SH.Get_Selected_Identity (Buffer)));
      end if;
   end;

end Extension_Parser;
