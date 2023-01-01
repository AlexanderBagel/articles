unit RawScanner.Types;

interface

uses
  Windows,
  Generics.Collections;

const
  Space = ' ';
  Arrow = ' -> ';

type
  PULONG_PTR64 = ^ULONG_PTR64;
  ULONG_PTR64 = UInt64;

  TModuleData = record
    ImageBase: ULONG_PTR64;
    Is64Image,
    IsDll,
    IsBaseValid,
    IsILCoreImage,
    IsRedirected: Boolean;
    ImagePath: string;
    function IsEmpty: Boolean;
  end;
  TModuleList = TList<TModuleData>;

  UNICODE_STRING32 = record
    Length, MaximumLength: USHORT;
    Buffer: ULONG;
  end;

  UNICODE_STRING64 = record
    Length, MaximumLength: USHORT;
    Buffer: ULONG_PTR64;
  end;

implementation

{ TModuleData }

function TModuleData.IsEmpty: Boolean;
begin
  Result := Self.ImageBase = 0;
end;

end.
