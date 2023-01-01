unit RawScanner.Utils;

interface

uses
  Windows,
  SysUtils,
  StrUtils,
  ImageHlp,
  RawScanner.Types,
  RawScanner.Wow64;

  function ReadRemoteMemory(hProcess: THandle; const lpBaseAddress: ULONG_PTR64;
    lpBuffer: Pointer; nSize: SIZE_T): Boolean;
  function UnDecorateSymbolName(const Value: string): string;

implementation

function ReadRemoteMemory(hProcess: THandle; const lpBaseAddress: ULONG_PTR64;
  lpBuffer: Pointer; nSize: SIZE_T): Boolean;
var
  {$IFDEF WIN32}
  uReturnLength: ULONG64;
  {$ENDIF}
  ReturnLength: NativeUInt;
begin
  {$IFDEF WIN32}
  if Wow64Support.Use64AddrMode then
    Result := Wow64Support.ReadVirtualMemory(hProcess, lpBaseAddress,
      lpBuffer, nSize, uReturnLength)
  else
    Result := ReadProcessMemory(hProcess, Pointer(lpBaseAddress),
      lpBuffer, nSize, ReturnLength);
  {$ELSE}
  Result := ReadProcessMemory(hProcess, Pointer(lpBaseAddress),
    lpBuffer, nSize, ReturnLength);
  {$ENDIF}
end;

function UnDecorateSymbolName(const Value: string): string;
const
  BuffLen = 4096;
var
  Index, Index2: Integer;
  TmpDecName, UnDecName: AnsiString;
begin
  // аналог функции SymUnDNameInternal используемой символами
  Result := Value;
  if Result = EmptyStr then Exit;
  if (Result[1] = '?') or Result.StartsWith('.?') or Result.StartsWith('..?') then
  begin
    Index := Pos('?', Value);
    TmpDecName := AnsiString(PChar(@Value[Index]));
    SetLength(UnDecName, BuffLen);
    SetLength(UnDecName, ImageHlp.UnDecorateSymbolName(@TmpDecName[1],
      @UnDecName[1], BuffLen, UNDNAME_NAME_ONLY));
    if Length(UnDecName) > 0 then
      Result := StringOfChar('.', Index - 1) + string(UnDecName);
    Exit;
  end;
  Index := 1;
  if CharInSet(Value[1], ['_', '.', '@']) then
    Inc(Index);
  Index2 := PosEx('@', Value, Index);
  if Index2 <> 0 then
    Index := Index2 + 1;
  if Index > 1 then
    Result := Copy(Value, Index, Length(Value));
end;

end.
