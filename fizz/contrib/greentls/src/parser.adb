with CPP;
with RFLX.Types; use type RFLX.Types.Byte; use type RFLX.Types.Length_Type;
with RFLX.TLS_Alert.Alert; use RFLX.TLS_Alert;
with RFLX.TLS_Handshake; use RFLX.TLS_Handshake;
with RFLX.TLS_Handshake.Handshake;
with RFLX.TLS_Handshake.Contains;
with RFLX.TLS_Handshake.Client_Hello;
with RFLX.TLS_Handshake.Server_Hello;
with RFLX.TLS_Handshake.New_Session_Ticket;
with RFLX.TLS_Handshake.Encrypted_Extensions;
with RFLX.TLS_Handshake.Certificate;
with RFLX.TLS_Handshake.Certificate_Entries;
with RFLX.TLS_Handshake.Certificate_Entry;
with RFLX.TLS_Handshake.Certificate_Request;
with RFLX.TLS_Handshake.Certificate_Verify;
with RFLX.TLS_Handshake.Finished;
with RFLX.TLS_Handshake.Key_Update;
with RFLX.TLS_Handshake.Cipher_Suites;
with RFLX.TLS_Handshake.Extensions;
with RFLX.TLS_Handshake.Extension;

package body Parser with
  SPARK_Mode
is

   procedure Parse_Extensions (Buffer :        RFLX.Types.Bytes;
                               Count  :    out CPP.Uint8_T;
                               Result : in out CPP.Extension_Record_Array) with
     Pre => Extensions.Is_Contained (Buffer)
            and then Result'Length > 0
            and then Result'Length < 256
   is
      Index  : Integer := Result'First - 1;
      Cursor : Extensions.Cursor_Type;
      Tag    : Extension_Type;
   begin
      Cursor := Extensions.First (Buffer);
      while Index < Result'Last and then Extensions.Valid_Element (Buffer, Cursor) loop
         declare
            Cf : constant RFLX.Types.Index_Type := Cursor.First;
            Cl : constant RFLX.Types.Index_Type := Cursor.Last;
         begin
            pragma Loop_Invariant (Index + 1 >= Result'First and Index + 1 <= Result'Last);
            pragma Loop_Invariant (Cf = Cursor.First and then Cl = Cursor.Last);
            pragma Loop_Invariant (Cf >= Buffer'First and then Cl <= Buffer'Last);
            pragma Loop_Invariant (Extension.Is_Contained (Buffer (Cf .. Cl)));
            pragma Loop_Invariant (Extension.Is_Valid (Buffer (Cf .. Cl)));
         end;

         Index := Index + 1;
         Tag := Extension.Get_Tag (Buffer (Cursor.First .. Cursor.Last));
         if Tag.Known then
            Result (Index) := (Tag => CPP.Uint16_T (Convert_To_Extension_Type_Base (Tag.Enum)),
                               Length => CPP.Uint16_T (Extension.Get_Extension_Data_Length (Buffer (Cursor.First .. Cursor.Last))),
                               Offset => CPP.Uint32_T (Cursor.First + 3));
         else  --  FIXME: Fizz expects also to get unknown extensions from parser
            Result (Index) := (Tag => CPP.Uint16_T (Tag.Raw),
                               Length => CPP.Uint16_T (Extension.Get_Extension_Data_Length (Buffer (Cursor.First .. Cursor.Last))),
                               Offset => CPP.Uint32_T (Cursor.First + 3));
         end if;

         Extensions.Next (Buffer, Cursor);
      end loop;

      Count := CPP.Uint8_T (Index - Result'First + 1);
   end Parse_Extensions;

   procedure Parse_Client_Hello (Buffer       :     RFLX.Types.Bytes;
                                 Result       : out CPP.Handshake_Record) with
     Pre => Client_Hello.Is_Contained (Buffer)
   is
   begin
      if Client_Hello.Is_Valid (Buffer) then
         declare
            Random_First             : RFLX.Types.Index_Type;
            Random_Last              : RFLX.Types.Index_Type;
            Random                   : RFLX.Types.Bytes (1 .. 32);
            Legacy_Session_ID_Length : Legacy_Session_ID_Length_Type;
            Legacy_Session_ID_First  : RFLX.Types.Index_Type;
            Legacy_Session_ID_Last   : RFLX.Types.Index_Type;
            Legacy_Session_ID        : RFLX.Types.Bytes (1 .. 256) := (others => 0);
            Cipher_Suites_Count      : Natural := 0;
            Cipher_Suites_Cursor     : Cipher_Suites.Cursor_Type;
            Cipher_Suites_First      : RFLX.Types.Index_Type;
            Cipher_Suites_Last       : RFLX.Types.Index_Type;
            Cipher_Suite_List        : CPP.Uint16_T_Array (1 .. 4) := (others => 0);
            Extensions_Count         : CPP.Uint8_T;
            Extensions_First         : RFLX.Types.Index_Type;
            Extensions_Last          : RFLX.Types.Index_Type;
            Extension_List           : CPP.Extension_Record_Array (1 .. 8) := (others => (0, 0, 0));
         begin
            Legacy_Session_ID_Length := Client_Hello.Get_Legacy_Session_ID_Length (Buffer);
            Client_Hello.Get_Legacy_Session_ID (Buffer, Legacy_Session_ID_First, Legacy_Session_ID_Last);
            Legacy_Session_ID (Legacy_Session_ID'First .. Legacy_Session_ID'First + RFLX.Types.Length_Type (Legacy_Session_ID_Length) - 1) :=
              Buffer (Legacy_Session_ID_First .. Legacy_Session_ID_Last);

            Client_Hello.Get_Random (Buffer, Random_First, Random_Last);
            Random := Buffer (Random_First .. Random_Last);

            Client_Hello.Get_Cipher_Suites (Buffer, Cipher_Suites_First, Cipher_Suites_Last);
            Cipher_Suites_Cursor := Cipher_Suites.First (Buffer (Cipher_Suites_First .. Cipher_Suites_Last));
            while Cipher_Suites_Count < Cipher_Suite_List'Last and then Cipher_Suites.Valid_Element (Buffer (Cipher_Suites_First .. Cipher_Suites_Last), Cipher_Suites_Cursor) loop
               Cipher_Suites_Count := Cipher_Suites_Count + 1;
               Cipher_Suite_List (Cipher_Suites_Count) := CPP.Uint16_T (Convert_To_Cipher_Suite_Type_Base (Cipher_Suites.Get_Element (Buffer (Cipher_Suites_First .. Cipher_Suites_Last), Cipher_Suites_Cursor)));
               Cipher_Suites.Next (Buffer (Cipher_Suites_First .. Cipher_Suites_Last), Cipher_Suites_Cursor);
            end loop;

            Client_Hello.Get_Extensions (Buffer, Extensions_First, Extensions_Last);
            Parse_Extensions (Buffer (Extensions_First .. Extensions_Last), Extensions_Count, Extension_List);

            Result := (Tag => 1,
                       Content => (Tag => 1,
                                   Client_Hello => (Random,
                                                    RFLX.Types.Byte (Client_Hello.Get_Legacy_Session_ID_Length (Buffer)),
                                                    Legacy_Session_ID,
                                                    RFLX.Types.Byte (Cipher_Suites_Count),
                                                    Cipher_Suite_List,
                                                    Extensions_Count,
                                                    Extension_List)));
         end;
      else
         Result := (Tag => 0, Content => (Tag => 0));
      end if;
   end Parse_Client_Hello;

   procedure Parse_Server_Hello (Buffer       :     RFLX.Types.Bytes;
                                 Result       : out CPP.Handshake_Record) with
     Pre => Server_Hello.Is_Contained (Buffer)
   is
   begin
      if Server_Hello.Is_Valid (Buffer) then
         declare
            Random_First             : RFLX.Types.Index_Type;
            Random_Last              : RFLX.Types.Index_Type;
            Random                   : RFLX.Types.Bytes (1 .. 32);
            Legacy_Session_ID_Length : Legacy_Session_ID_Length_Type;
            Legacy_Session_ID_First  : RFLX.Types.Index_Type;
            Legacy_Session_ID_Last   : RFLX.Types.Index_Type;
            Legacy_Session_ID        : RFLX.Types.Bytes (1 .. 256) := (others => 0);
            Cipher_Suite             : Cipher_Suite_Type;
            Extensions_Count         : CPP.Uint8_T;
            Extensions_First         : RFLX.Types.Index_Type;
            Extensions_Last          : RFLX.Types.Index_Type;
            Extension_List           : CPP.Extension_Record_Array (1 .. 8) := (others => (0, 0, 0));
         begin
            Legacy_Session_ID_Length := Server_Hello.Get_Legacy_Session_ID_Length (Buffer);
            Server_Hello.Get_Legacy_Session_ID (Buffer, Legacy_Session_ID_First, Legacy_Session_ID_Last);
            Legacy_Session_ID (Legacy_Session_ID'First .. Legacy_Session_ID'First + RFLX.Types.Length_Type (Legacy_Session_ID_Length) - 1) :=
              Buffer (Legacy_Session_ID_First .. Legacy_Session_ID_Last);

            Server_Hello.Get_Random (Buffer, Random_First, Random_Last);
            Random := Buffer (Random_First .. Random_Last);

            Cipher_Suite := Server_Hello.Get_Cipher_Suite (Buffer);

            Server_Hello.Get_Extensions (Buffer, Extensions_First, Extensions_Last);
            Parse_Extensions (Buffer (Extensions_First .. Extensions_Last), Extensions_Count, Extension_List);

            Result := (Tag => 2,
                       Content => (Tag => 2,
                                   Server_Hello => (Random,
                                                    RFLX.Types.Byte (Server_Hello.Get_Legacy_Session_ID_Length (Buffer)),
                                                    Legacy_Session_ID,
                                                    CPP.Uint16_T (Convert_To_Cipher_Suite_Type_Base (Cipher_Suite)),
                                                    Extensions_Count,
                                                    Extension_List)));
         end;
      else
         Result := (Tag => 0, Content => (Tag => 0));
      end if;
   end Parse_Server_Hello;

   procedure Parse_New_Session_Ticket (Buffer       :     RFLX.Types.Bytes;
                                       Result       : out CPP.Handshake_Record) with
     Pre => New_Session_Ticket.Is_Contained (Buffer)
   is
   begin
      if New_Session_Ticket.Is_Valid (Buffer) then
         declare
            Ticket_Lifetime     : Ticket_Lifetime_Type;
            Ticket_Age_Add      : Ticket_Age_Add_Type;
            Ticket_Nonce_Length : Ticket_Nonce_Length_Type;
            Ticket_Nonce_First  : RFLX.Types.Index_Type;
            Ticket_Length       : Ticket_Length_Type;
            Ticket_First        : RFLX.Types.Index_Type;
            Extensions_Count    : CPP.Uint8_T;
            Extensions_First    : RFLX.Types.Index_Type;
            Extensions_Last     : RFLX.Types.Index_Type;
            Extension_List      : CPP.Extension_Record_Array (1 .. 8) := (others => (0, 0, 0));
         begin
            Ticket_Lifetime := New_Session_Ticket.Get_Ticket_Lifetime (Buffer);

            Ticket_Age_Add := New_Session_Ticket.Get_Ticket_Age_Add (Buffer);

            Ticket_Nonce_Length := New_Session_Ticket.Get_Ticket_Nonce_Length (Buffer);
            Ticket_Nonce_First := New_Session_Ticket.Get_Ticket_Nonce_First (Buffer);

            Ticket_Length := New_Session_Ticket.Get_Ticket_Length (Buffer);
            Ticket_First := New_Session_Ticket.Get_Ticket_First (Buffer);

            New_Session_Ticket.Get_Extensions (Buffer, Extensions_First, Extensions_Last);
            Parse_Extensions (Buffer (Extensions_First .. Extensions_Last), Extensions_Count, Extension_List);

            Result := (Tag => 4,
                       Content => (Tag => 4,
                                   New_Session_Ticket => (CPP.Uint32_T (Ticket_Lifetime),
                                                          CPP.Uint32_T (Ticket_Age_Add),
                                                          CPP.Uint32_T (Ticket_Nonce_Length),
                                                          CPP.Uint32_T (Ticket_Nonce_First - 1),
                                                          CPP.Uint32_T (Ticket_Length),
                                                          CPP.Uint32_T (Ticket_First - 1),
                                                          Extensions_Count,
                                                          Extension_List)));
         end;
      else
         Result := (Tag => 0, Content => (Tag => 0));
      end if;
   end Parse_New_Session_Ticket;

   procedure Parse_End_Of_Early_Data (Buffer       :     RFLX.Types.Bytes;
                                      Result       : out CPP.Handshake_Record)
   is
   begin
      pragma Unreferenced (Buffer);
      Result := (Tag => 5, Content => (Tag => 5));
   end Parse_End_Of_Early_Data;

   procedure Parse_Encrypted_Extensions (Buffer       :     RFLX.Types.Bytes;
                                         Result       : out CPP.Handshake_Record) with
     Pre => Encrypted_Extensions.Is_Contained (Buffer)
   is
   begin
      if Encrypted_Extensions.Is_Valid (Buffer) then
         declare
            Extensions_Count : CPP.Uint8_T;
            Extensions_First : RFLX.Types.Index_Type;
            Extensions_Last  : RFLX.Types.Index_Type;
            Extension_List   : CPP.Extension_Record_Array (1 .. 8) := (others => (0, 0, 0));
         begin
            Encrypted_Extensions.Get_Extensions (Buffer, Extensions_First, Extensions_Last);
            Parse_Extensions (Buffer (Extensions_First .. Extensions_Last), Extensions_Count, Extension_List);

            Result := (Tag => 8,
                       Content => (Tag => 8,
                                   Encrypted_Extensions => (Extensions_Count,
                                                            Extension_List)));
         end;
      else
         Result := (Tag => 0, Content => (Tag => 0));
      end if;
   end Parse_Encrypted_Extensions;

   procedure Parse_Certificate_Entries (Buffer :        RFLX.Types.Bytes;
                                        Count  :    out CPP.Uint8_T;
                                        Result : in out CPP.Certificate_Entry_Record_Array) with
     Pre => Certificate_Entries.Is_Contained (Buffer)
            and then Result'Length > 0
            and then Result'Length < 256
   is
      Index  : Integer := Result'First - 1;
      Cursor : Certificate_Entries.Cursor_Type;
   begin
      Cursor := Certificate_Entries.First (Buffer);
      while Index < Result'Last and then Certificate_Entries.Valid_Element (Buffer, Cursor) loop
         declare
            Cf : constant RFLX.Types.Index_Type := Cursor.First;
            Cl : constant RFLX.Types.Index_Type := Cursor.Last;
         begin
            pragma Loop_Invariant (Index + 1 >= Result'First and Index + 1 <= Result'Last);
            pragma Loop_Invariant (Cf = Cursor.First and then Cl = Cursor.Last);
            pragma Loop_Invariant (Cf >= Buffer'First and then Cl <= Buffer'Last);
            pragma Loop_Invariant (Certificate_Entry.Is_Contained (Buffer (Cf .. Cl)));
            pragma Loop_Invariant (Certificate_Entry.Is_Valid (Buffer (Cf .. Cl)));
         end;

         Index := Index + 1;

         declare
            Cert_Data_Length : Cert_Data_Length_Type;
            Cert_Data_First  : RFLX.Types.Index_Type;
            Extensions_Count : CPP.Uint8_T;
            Extensions_First : RFLX.Types.Index_Type;
            Extensions_Last  : RFLX.Types.Index_Type;
            Extension_List   : CPP.Extension_Record_Array (1 .. 8) := (others => (0, 0, 0));
         begin
            Cert_Data_Length := Certificate_Entry.Get_Cert_Data_Length (Buffer (Cursor.First .. Cursor.Last));
            Cert_Data_First := Certificate_Entry.Get_Cert_Data_First (Buffer (Cursor.First .. Cursor.Last));
            Certificate_Entry.Get_Extensions (Buffer (Cursor.First .. Cursor.Last), Extensions_First, Extensions_Last);
            Parse_Extensions (Buffer (Extensions_First .. Extensions_Last), Extensions_Count, Extension_List);

            Result (Index) := (CPP.Uint32_T (Cert_Data_Length),
                               CPP.Uint32_T (Cert_Data_First - 1),
                               Extensions_Count,
                               Extension_List);
         end;

         Certificate_Entries.Next (Buffer, Cursor);
      end loop;

      Count := CPP.Uint8_T (Index - Result'First + 1);
   end Parse_Certificate_Entries;

   procedure Parse_Certificate (Buffer :     RFLX.Types.Bytes;
                                Result : out CPP.Handshake_Record) with
     Pre => Certificate.Is_Contained (Buffer)
   is
   begin
      if Certificate.Is_Valid (Buffer) then
         declare
            Context_Length     : Certificate_Request_Context_Length_Type;
            Context_First      : RFLX.Types.Index_Type;
            Certificates_Count : CPP.Uint8_T;
            Certificates_First : RFLX.Types.Index_Type;
            Certificates_Last  : RFLX.Types.Index_Type;
            Extension_List     : CPP.Extension_Record_Array (1 .. 8) := (others => (0, 0, 0));
            Certificate_List   : CPP.Certificate_Entry_Record_Array (1 .. 8) := (others => (0, 0, 0, Extension_List));
         begin
            Context_Length := Certificate.Get_Certificate_Request_Context_Length (Buffer);
            Context_First := Certificate.Get_Certificate_Request_Context_First (Buffer);
            Certificate.Get_Certificate_List (Buffer, Certificates_First, Certificates_Last);
            Parse_Certificate_Entries (Buffer (Certificates_First .. Certificates_Last), Certificates_Count, Certificate_List);

            Result := (Tag => 11,
                       Content => (Tag => 11,
                                   Certificate => (CPP.Uint32_T (Context_Length),
                                                   CPP.Uint32_T (Context_First - 1),
                                                   Certificates_Count,
                                                   Certificate_List)));
         end;
      else
         Result := (Tag => 0, Content => (Tag => 0));
      end if;
   end Parse_Certificate;

   procedure Parse_Certificate_Request (Buffer :     RFLX.Types.Bytes;
                                        Result : out CPP.Handshake_Record) with
     Pre => Certificate_Request.Is_Contained (Buffer)
   is
   begin
      if Certificate_Request.Is_Valid (Buffer) then
         declare
            Length           : Certificate_Request_Context_Length_Type;
            First            : RFLX.Types.Index_Type;
            Extensions_Count : CPP.Uint8_T;
            Extensions_First : RFLX.Types.Index_Type;
            Extensions_Last  : RFLX.Types.Index_Type;
            Extension_List   : CPP.Extension_Record_Array (1 .. 8) := (others => (0, 0, 0));
         begin
            Length := Certificate_Request.Get_Certificate_Request_Context_Length (Buffer);
            First := Certificate_Request.Get_Certificate_Request_Context_First (Buffer);
            Certificate_Request.Get_Extensions (Buffer, Extensions_First, Extensions_Last);
            Parse_Extensions (Buffer (Extensions_First .. Extensions_Last), Extensions_Count, Extension_List);

            Result := (Tag => 13,
                       Content => (Tag => 13,
                                   Certificate_Request => (CPP.Uint32_T (Length),
                                                           CPP.Uint32_T (First - 1),
                                                           Extensions_Count,
                                                           Extension_List)));
         end;
      else
         Result := (Tag => 0, Content => (Tag => 0));
      end if;
   end Parse_Certificate_Request;

   procedure Parse_Certificate_Verify (Buffer       :     RFLX.Types.Bytes;
                                       Result       : out CPP.Handshake_Record) with
     Pre => Certificate_Verify.Is_Contained (Buffer)
   is
   begin
      if Certificate_Verify.Is_Valid (Buffer) then
         declare
            Algorithm : Signature_Scheme;
            Length    : Signature_Length_Type;
            First     : RFLX.Types.Index_Type;
         begin
            Algorithm := Certificate_Verify.Get_Algorithm (Buffer);
            Length := Certificate_Verify.Get_Signature_Length (Buffer);
            First := Certificate_Verify.Get_Signature_First (Buffer);

            Result := (Tag => 15,
                       Content => (Tag => 15,
                                   Certificate_Verify => (CPP.Uint16_T (Convert_To_Signature_Scheme_Base (Algorithm)),
                                                          CPP.Uint32_T (Length),
                                                          CPP.Uint32_T (First - 1))));
         end;
      else
         Result := (Tag => 0, Content => (Tag => 0));
      end if;
   end Parse_Certificate_Verify;

   procedure Parse_Finished (Buffer       :     RFLX.Types.Bytes;
                             Result       : out CPP.Handshake_Record) with
     Pre => Finished.Is_Contained (Buffer)
   is
   begin
      if Finished.Is_Valid (Buffer) then
         declare
            First : RFLX.Types.Index_Type;
            Last  : RFLX.Types.Index_Type;
         begin
            Finished.Get_Verify_Data (Buffer, First, Last);

            Result := (Tag => 20,
                       Content => (Tag => 20,
                                   Finished => (CPP.Uint32_T (Last - First + 1),
                                                CPP.Uint32_T (First - 1))));
         end;
      else
         Result := (Tag => 0, Content => (Tag => 0));
      end if;
   end Parse_Finished;

   procedure Parse_Key_Update (Buffer       :     RFLX.Types.Bytes;
                               Result       : out CPP.Handshake_Record) with
     Pre => Key_Update.Is_Contained (Buffer)
   is
   begin
      if Key_Update.Is_Valid (Buffer) then
         declare
            Request_Update : Key_Update_Request;
         begin
            Request_Update := Key_Update.Get_Request_Update (Buffer);

            Result := (Tag => 24,
                       Content => (Tag => 24,
                                   Key_Update => (Request_Update => CPP.Uint8_T (Convert_To_Key_Update_Request_Base (Request_Update)))));
         end;
      else
         Result := (Tag => 0, Content => (Tag => 0));
      end if;
   end Parse_Key_Update;

   procedure Parse_Handshake_Message (Buffer :     RFLX.Types.Bytes;
                                      Result : out CPP.Handshake_Record) is
      First          : RFLX.Types.Index_Type;
      Last           : RFLX.Types.Index_Type;
      Tag            : CPP.Uint8_T;
   begin
      Result := (Tag => 0, Content => (Tag => 0));

      Handshake.Label (Buffer);
      if Handshake.Is_Valid (Buffer) then

         Handshake.Get_Payload (Buffer, First, Last);

         if Contains.Client_Hello_Handshake (Buffer) then
            Parse_Client_Hello (Buffer (First .. Last), Result);

         elsif Contains.Server_Hello_Handshake (Buffer) then
            Parse_Server_Hello (Buffer (First .. Last), Result);

         elsif Contains.New_Session_Ticket_Handshake (Buffer) then
            Parse_New_Session_Ticket (Buffer (First .. Last), Result);

         elsif Contains.End_Of_Early_Data_Handshake (Buffer) then
            Parse_End_Of_Early_Data (Buffer (First .. Last), Result);

         elsif Contains.Encrypted_Extensions_Handshake (Buffer) then
            Parse_Encrypted_Extensions (Buffer (First .. Last), Result);

         elsif Contains.Certificate_Handshake (Buffer) then
            Parse_Certificate (Buffer (First .. Last), Result);

         elsif Contains.Certificate_Request_Handshake (Buffer) then
            Parse_Certificate_Request (Buffer (First .. Last), Result);

         elsif Contains.Certificate_Verify_Handshake (Buffer) then
            Parse_Certificate_Verify (Buffer (First .. Last), Result);

         elsif Contains.Finished_Handshake (Buffer) then
            Parse_Finished (Buffer (First .. Last), Result);

         elsif Contains.Key_Update_Handshake (Buffer) then
            Parse_Key_Update (Buffer (First .. Last), Result);

         else
            Tag := CPP.Uint8_T (Convert_To_Handshake_Type_Base (Handshake.Get_Tag (Buffer)));
            Result := (Tag => Tag, Content => (Tag => 0));

         end if;

      end if;
   end Parse_Handshake_Message;

   procedure Parse_Alert_Message (Buffer :     RFLX.Types.Bytes;
                                  Result : out CPP.Alert_Record) is
      Level       : Alert_Level;
      Description : Alert_Description;
   begin
      Result := (Level => 255, Description => 255);

      Alert.Label (Buffer);
      if Alert.Is_Valid (Buffer) then

         Level := Alert.Get_Level (Buffer);
         Description := Alert.Get_Description (Buffer);

         Result := (Level => CPP.Uint8_T (Convert_To_Alert_Level_Base (Level)),
                    Description => CPP.Uint8_T (Convert_To_Alert_Description_Base (Description)));
      end if;
   end Parse_Alert_Message;

end Parser;
