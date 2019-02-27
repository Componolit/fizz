package GreenTLS is

    procedure Hello_World
        with Global => null,
             Export => True,
             Convention => C,
             External_Name => "hello_world";

end GreenTLS;
