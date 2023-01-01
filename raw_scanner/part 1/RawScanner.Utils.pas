unit RawScanner.Utils;

interface

uses
  SysUtils,
  StrUtils,
  ImageHlp;

  function UnDecorateSymbolName(const Value: string): string;

implementation

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
