unit RawScanner.Types;

interface

uses
  Windows,
  Generics.Collections;

const
  Space = ' ';
  Arrow = ' -> ';

type
  THookType = (htImport, htDelayedImport, htExport, htCode);
  THookTypes = set of THookType;

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

  TMemoryBasicInformation64 = record
    BaseAddress : ULONG_PTR64;
    AllocationBase : ULONG_PTR64;
    AllocationProtect : DWORD;
    RegionSize : ULONG_PTR64;
    State : DWORD;
    Protect : DWORD;
    Type_9 : DWORD;
  end;

implementation

{ TModuleData }

function TModuleData.IsEmpty: Boolean;
begin
  Result := Self.ImageBase = 0;
end;

end.
