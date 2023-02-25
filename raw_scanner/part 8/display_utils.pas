unit display_utils;

interface

uses
  Windows,
  SysUtils,
  Classes,
  Math,
  Generics.Collections,
  RawScanner.Core,
  RawScanner.Types,
  RawScanner.ModulesData,
  RawScanner.Analyzer,
  RawScanner.Utils,
  Debug.TinyLenDisAsm;

var
  ImportCount,
  DImportCount,
  ExportCount,
  CodeCount: Integer;

  procedure ShowModuleInfo(Index: Integer; Module: TRawPEImage);
  procedure ProcessTableHook(const Data: THookData);
  procedure ProcessCodeHook(const Data: TCodeHookData);

implementation

type
  TCalculateHookData = record
    ProcessHandle: THandle;
    AddrVA, ImageBase,
    LimitMin, LimitMax: ULONG_PTR64;
    Is64Code: Boolean;
    LibraryFuncName, HookHandlerModule: string;
    HookType: THookType;
    DumpStrings: TStringList;
  end;

const
  Separator = '|';
  HexPfx = '0x';
  PatchedPfx = '. Status: PATCHED!';
  ModifiedPfx = '. Status: Modified. Probably wrong detect.';
  ExpectedPfx = 'Expected: ';
  PresentPfx = ', present: ';
  AddrPfx = ', at address: ';

function InitCalculateHookData: TCalculateHookData; overload;
begin
  ZeroMemory(@Result, SizeOf(TCalculateHookData));
  Result.DumpStrings := TStringList.Create;
end;

function InitCalculateHookData(const Data: THookData): TCalculateHookData; overload;
begin
  Result := InitCalculateHookData;
  Result.ProcessHandle := Data.ProcessHandle;
  Result.AddrVA := Data.AddrVA;
  Result.ImageBase := Data.ImageBase;
  Result.Is64Code := Data.Image64;
  Result.HookType := Data.HookType;
  Result.LibraryFuncName := Data.FuncName;
end;

function InitCalculateHookData(const CodeData: TCodeHookData): TCalculateHookData; overload;
begin
  Result := InitCalculateHookData;
  Result.ProcessHandle := CodeData.ProcessHandle;
  Result.AddrVA := CodeData.AddrVA;
  Result.ImageBase := CodeData.ImageBase;
  Result.Is64Code := CodeData.Image64;
  Result.HookType := htCode;
  Result.LibraryFuncName := CodeData.ExportFunc;
end;

procedure ReleaseCalculateHookData(const Value: TCalculateHookData);
begin
  Value.DumpStrings.Free;
end;

const
  DefaultBuffSize = 64;

procedure ShowModuleInfo(Index: Integer; Module: TRawPEImage);
const
  Step = 'Loading... ';
var
  BitStr, FlagStr: string;

  function AddFlagStr(const Value: string): string;
  begin
    if FlagStr = EmptyStr then
      Result := Value
    else
      Result := FlagStr + ', ' + Value;
  end;

begin
  FlagStr := EmptyStr;
  if Module.Rebased then
    FlagStr := 'REBASED';
  if Module.ComPlusILOnly then
    FlagStr := AddFlagStr('IL_CORE');
  if Module.Redirected then
    FlagStr := AddFlagStr('REDIRECTED');

  if Module.Image64 then
    BitStr := '[x64] ' + IntToHex(Module.ImageBase) + Space
  else
    BitStr := IntToHex(Module.ImageBase, 8) + Space;

  if FlagStr <> EmptyStr then
    FlagStr := ' (' + FlagStr + ')';

  Writeln(Index + 1, ': ', Step, BitStr, Module.ImagePath, FlagStr);
end;

procedure AddTableHeader(RawOffset: DWORD; cdh: TCalculateHookData);
var
  Line, HexStr: string;
begin
  HexStr := HexPfx + IntToHex(RawOffset, 0);
  Line := 'Addr:' + StringOfChar(Space, 11) + '|Raw (' +
    HexPfx + IntToHex(RawOffset, 0) + '):';
  Line := Line +
    StringOfChar(Space, 51 - Length(HexStr)) +
    '|Remote:';
  cdh.DumpStrings.Add(Line);
  cdh.DumpStrings.Add(StringOfChar('-', 124));
end;

procedure ProcessTableHook(const Data: THookData);

  function ByteToHexStr(Value: PByte): string;
  begin
    Result := '';
    for var I := 0 to 3 do
    begin
      Result := Result + IntToHex(Value^, 2) + Space;
      Inc(Value);
    end;
    Result := Result + StringOfChar(Space, 46);
  end;

const
  ExMiss = 'Export record missing, present: ';

var
  chd: TCalculateHookData;
  Pfx, ExternalModule: string;
begin
  Pfx := EmptyStr;
  chd := InitCalculateHookData(Data);
  try

    chd.DumpStrings.Add(EmptyStr);

    chd.HookHandlerModule := GetMappedModule(Data.ProcessHandle, Data.RemoteVA);
    ExternalModule := chd.HookHandlerModule;

    if not ExternalModule.IsEmpty then
      ExternalModule := ' --> ' + ExternalModule;

    if Data.HookType <> htExport then
    begin
      case Data.HookType of
        htImport: Pfx := 'Import';
        htDelayedImport: Pfx := 'Delayed import';
      end;
      chd.DumpStrings.Add(Pfx + ' modified ' + Data.ModuleName + ' -> ' +
        Data.FuncName + AddrPfx + IntToHex(Data.AddrVA, 1));
      if Data.Calculated or (Data.HookType = htDelayedImport) then
        chd.DumpStrings.Add(ExpectedPfx + IntToHex(Data.RawVA) +
          PresentPfx + IntToHex(Data.RemoteVA) + ExternalModule)
      else
        if Data.ImportAdv.ForvardedTo <> EmptyStr then
          chd.DumpStrings.Add(ExMiss + IntToHex(Data.RemoteVA) +
            ', forvarded to "' + Data.ImportAdv.ForvardedTo + '"' + ExternalModule)
        else
          chd.DumpStrings.Add(ExMiss + IntToHex(Data.RemoteVA) + ExternalModule);
    end
    else
    begin
      Pfx := 'Export modified ' + Data.ModuleName + ' -> ' + Data.FuncName;

      if Data.ExportAdv.Patched then
        chd.DumpStrings.Add(Pfx + PatchedPfx)
      else
        chd.DumpStrings.Add(Pfx + ModifiedPfx);

      if Data.Calculated then
      begin
        chd.DumpStrings.Add(ExpectedPfx + IntToHex(Data.RawVA) +
          PresentPfx + IntToHex(Data.RemoteVA) + ExternalModule);
        AddTableHeader(Data.ExportAdv.RawOffset, chd);
        chd.DumpStrings.Add(IntToHex(Data.AddrVA, 16) + Separator +
          ByteToHexStr(@Data.ExportAdv.ExpRawRva) + Separator +
          ByteToHexStr(@Data.ExportAdv.ExpRemoteRva));
      end
      else
        chd.DumpStrings.Add(ExMiss + IntToHex(Data.RemoteVA) + ExternalModule);
    end;

    case Data.HookType of
      htImport: Inc(ImportCount);
      htDelayedImport: Inc(DImportCount);
      htExport: Inc(ExportCount);
    end;

    for var I := 0 to chd.DumpStrings.Count - 1 do
      Writeln(chd.DumpStrings[I]);

  finally
    ReleaseCalculateHookData(chd);
  end;

end;

procedure ProcessCodeHook(const Data: TCodeHookData);

  function ByteToHexStr(Value: PByte; BuffSize: Integer): string;
  begin
    Result := '';
    for var I := 0 to BuffSize - 1 do
    begin
      Result := Result + IntToHex(Value^, 2) + ' ';
      Inc(Value);
    end;
  end;

var
  I, OpcodeLen: Integer;
  rawCursor, remCursor: PByte;
  Index: Integer;
begin
  // поиск конца функции
  rawCursor := Data.Raw;
  I := Data.BufSize;
  while I > 0 do
  begin
    OpcodeLen := ldisasm(rawCursor, Data.Image64);
    Dec(I, OpcodeLen);
    // контроль выхода за размер буфера
    if I <= 0 then
    begin
      I := 0;
      Break;
    end;
    // просто ищем инструкцию RET
    if (OpcodeLen = 1) and (rawCursor^ = $C3) then
      Break;
    Inc(rawCursor, OpcodeLen);
  end;
  if CompareMem(Data.Raw, Data.Remote, Data.BufSize - I) then
    Exit;

  // убираем лишние байты с конца, которые были не изменены
  remCursor := Data.Remote + Data.BufSize - I - 1;
  rawCursor := Data.Raw + Data.BufSize - I - 1;
  while (I < Data.BufSize) and (remCursor^ = rawCursor^) do
  begin
    Inc(I);
    Dec(remCursor);
    Dec(rawCursor);
  end;

  Writeln;
  Write('Code modified ', Data.ExportFunc, AddrPfx, IntToHex(Data.AddrVA));
  if Data.Patched then
    Writeln(PatchedPfx)
  else
    Writeln(ModifiedPfx);
  Index := RawScannerCore.Modules.GetModule(Data.ImageBase);
  if Index >= 0 then
    Writeln('Image path: "', RawScannerCore.Modules.Items[Index].ImagePath,
      '", raw offset: ', IntToHex(Data.RawOffset));
  Writeln('  Expected: ' + ByteToHexStr(Data.Raw, Data.BufSize - I));
  Writeln('  Present:  ' + ByteToHexStr(Data.Remote, Data.BufSize - I));

  Inc(CodeCount);
end;

end.
