program test;

{$APPTYPE CONSOLE}

{$R *.res}

uses
  Windows,
  PsApi,
  System.SysUtils,
  RawScanner.ModulesData in 'RawScanner.ModulesData.pas',
  RawScanner.Types in 'RawScanner.Types.pas',
  RawScanner.Utils in 'RawScanner.Utils.pas',
  RawScanner.LoaderData in 'RawScanner.LoaderData.pas',
  RawScanner.Wow64 in 'RawScanner.Wow64.pas';

  function EnumProcessModulesEx(hProcess: THandle; lphModule: PHandle;
    cb: DWORD; var lpcbNeeded: DWORD; dwFilterFlag: DWORD): BOOL; stdcall;
    external 'psapi.dll';

procedure TestEnumSelfModules;
const
  LIST_MODULES_ALL = 3;
var
  Buff: array of THandle;
  Needed: DWORD;
  I: Integer;
  FileName: array[0..MAX_PATH] of Char;
begin
  EnumProcessModulesEx(GetCurrentProcess, nil, 0, Needed, LIST_MODULES_ALL);
  SetLength(Buff, Needed shr 2);
  if EnumProcessModulesEx(GetCurrentProcess, @Buff[0], Needed, Needed, LIST_MODULES_ALL) then
  begin
    for I := 0 to Integer(Needed) - 1 do
      if Buff[I] <> 0 then
      begin
        FillChar(FileName, MAX_PATH, 0);
        GetModuleFileNameEx(GetCurrentProcess, Buff[I], @FileName[1], MAX_PATH);
        Writeln(I, ': ', IntToHex(Buff[I], 1), ' ', string(PChar(@FileName[1])));
      end;
  end;
end;

type
  TPEB = record
    InheritedAddressSpace: BOOLEAN;
    ReadImageFileExecOptions: BOOLEAN;
    BeingDebugged: BOOLEAN;
    BitField: BOOLEAN;
    Mutant: THandle;
    ImageBaseAddress: PVOID;
    LoaderData: PVOID;
  end;

  TPEB32 = record
    InheritedAddressSpace: BOOLEAN;
    ReadImageFileExecOptions: BOOLEAN;
    BeingDebugged: BOOLEAN;
    BitField: BOOLEAN;
    Mutant: ULONG;
    ImageBaseAddress: ULONG;
    LoaderData: ULONG;
  end;

  TPEB64 = record
    InheritedAddressSpace: BOOLEAN;
    ReadImageFileExecOptions: BOOLEAN;
    BeingDebugged: BOOLEAN;
    BitField: BOOLEAN;
    Mutant: ULONG_PTR64;
    ImageBaseAddress: ULONG_PTR64;
    LoaderData: ULONG_PTR64;
  end;

  PPROCESS_BASIC_INFORMATION = ^PROCESS_BASIC_INFORMATION;
  PROCESS_BASIC_INFORMATION = record
    ExitStatus: LONG;
    PebBaseAddress: PVOID;
    AffinityMask: ULONG_PTR;
    BasePriority: LONG;
    uUniqueProcessId: ULONG_PTR;
    uInheritedFromUniqueProcessId: ULONG_PTR;
  end;

  PPROCESS_BASIC_INFORMATION64 = ^PROCESS_BASIC_INFORMATION64;
  PROCESS_BASIC_INFORMATION64 = record
    ExitStatus: ULONG_PTR64;
    PebBaseAddress: ULONG_PTR64;
    AffinityMask: ULONG_PTR64;
    BasePriority: ULONG_PTR64;
    uUniqueProcessId: ULONG_PTR64;
    uInheritedFromUniqueProcessId: ULONG_PTR64;
  end;

  function NtQueryInformationProcess(ProcessHandle: Cardinal;
    ProcessInformationClass: Integer;
    ProcessInformation: Pointer;
    ProcessInformationLength: Cardinal;
    ReturnLength: PCardinal): NTSTATUS; stdcall; external 'ntdll.dll';

function Convert32PebTo64(const Value: TPEB32): TPEB64;
begin
  Result.InheritedAddressSpace := Value.InheritedAddressSpace;
  Result.ReadImageFileExecOptions := Value.ReadImageFileExecOptions;
  Result.BeingDebugged := Value.BeingDebugged;
  Result.BitField := Value.BitField;
  Result.Mutant := Value.Mutant;
  Result.ImageBaseAddress := Value.ImageBaseAddress;
  Result.LoaderData := Value.LoaderData;
end;

function ReadNativePeb(hProcess: THandle; out APeb: TPEB64): Boolean;
const
  ProcessBasicInformation = 0;
var
  PBI: PROCESS_BASIC_INFORMATION;
  dwReturnLength: Cardinal;
  NativePeb: TPEB;
begin
  // чтение PEB, совпадающего битностью с текущей сборкой
  Result := NtQueryInformationProcess(hProcess,
    ProcessBasicInformation, @PBI, SizeOf(PBI), @dwReturnLength) = 0;
  if not Result then
    Exit;

  Result := ReadRemoteMemory(hProcess, ULONG_PTR64(PBI.PebBaseAddress),
    @NativePeb, SizeOf(TPEB));
  if Result then
  {$IFDEF WIN32}
    APeb := Convert32PebTo64(TPEB32(NativePeb));
  {$ELSE}
    APeb := TPEB64(NativePeb);
  {$ENDIF}
end;

function Read64PebFrom32Bit(hProcess: THandle; out APeb: TPEB64): Boolean;
const
  ProcessBasicInformation = 0;
var
  PBI64: PROCESS_BASIC_INFORMATION64;
  dwReturnLength: Cardinal;
begin
  // Чтение 64 битного PEB из 32 битного кода производится через Wow64 обертку
  Result := Wow64Support.QueryInformationProcess(hProcess,
    ProcessBasicInformation, @PBI64, SizeOf(PBI64), dwReturnLength);
  if not Result then
    Exit;

  Result := ReadRemoteMemory(hProcess, PBI64.PebBaseAddress,
    @APeb, SizeOf(TPEB64));
end;

function Read32PebFrom64Bit(hProcess: THandle; out APeb: TPEB64): Boolean;
const
  ProcessWow64Information = 26;
var
  PebWow64BaseAddress: ULONG_PTR;
  dwReturnLength: Cardinal;
  Peb32: TPEB32;
begin
  // Чтение 32 битного PEB из 64 битного кода производится через PebWow64BaseAddress
  Result := NtQueryInformationProcess(hProcess,
    ProcessWow64Information, @PebWow64BaseAddress, SizeOf(ULONG_PTR),
    @dwReturnLength) = 0;
  if not Result then
    Exit;

  Result := ReadRemoteMemory(hProcess, PebWow64BaseAddress,
    @Peb32, SizeOf(TPEB32));
  if Result then
    APeb := Convert32PebTo64(Peb32);
end;

function ReadPeb(hProcess: THandle; Read32Peb: Boolean; out APeb: TPEB64): Boolean;
begin
  ZeroMemory(@APeb, SizeOf(TPEB64));
  if Read32Peb then
  {$IFDEF WIN32}
    Result := ReadNativePeb(hProcess, APeb)
  else
    Result := Read64PebFrom32Bit(hProcess, APeb);
  {$ELSE}
    Result := Read32PebFrom64Bit(hProcess, APeb)
  else
    Result := ReadNativePeb(hProcess, APeb);
  {$ENDIF}
end;

var
  hProcess: THandle;
  IsWow64Mode: LongBool;
  PEB32, PEB64: TPEB64;
  Loader, LocalLoader: TLoaderData;
  NtDll: TRawPEImage;
  Index: Integer;
begin
  hProcess := OpenProcess(
    PROCESS_QUERY_INFORMATION or PROCESS_VM_READ,
    False, GetCurrentProcessId);

  Wow64Support.IsWow64Process(hProcess, IsWow64Mode);

  // загружаем блоки окружения процесса (если есть)
  ReadPeb(hProcess, True, PEB32);
  ReadPeb(hProcess, False, PEB64);

  // Инициализация VA адреса 64 битной NtQueryVirtualMemory
  if IsWow64Mode then
  begin
    LocalLoader := TLoaderData.Create(hProcess, True);
    try
      // получаем данные только по 64 битным модулям
      if LocalLoader.Load64LoaderData(PEB64.LoaderData) > 0 then
        for var Module in LocalLoader.Modules do
        begin
          // ищем 64 битню ntdll
          if ExtractFileName(Module.ImagePath).ToLower = 'ntdll.dll' then
          begin
            // если нашли (а мы должны найти) инициализирем с учетом её инстанса
            // но перед этим отключаем редирект чтобы не подгрузилась 32 битная NTDLL из SysWow64
            Wow64Support.DisableRedirection;
            try
              NtDll := TRawPEImage.Create(Module.ImagePath, Module.ImageBase);
              try
                // и только теперь получаем адрес NtQueryVirtualMemory
                // который актуален применительно к нашему процессу
                Index := NtDll.ExportIndex('NtQueryVirtualMemory');
                if Index >= 0 then
                  SetNtQueryVirtualMemoryAddr(NtDll.ExportList.List[Index].FuncAddrVA);
              finally
                NtDll.Free;
              end;
            finally
              Wow64Support.EnableRedirection;
            end;
            Break;
          end;
        end;
    finally
      LocalLoader.Free;
    end;
  end;

  // полученые адреса списков загрузчика передаем лоадеру списков
  Loader := TLoaderData.Create(hProcess, IsWow64Mode);
  try
    Loader.Load32LoaderData(PEB32.LoaderData);
    Loader.Load64LoaderData(PEB64.LoaderData);
    Writeln(0, ': ', IntToHex(Loader.RootModule.ImageBase, 1), ' ', Loader.RootModule.ImagePath);
    for var I := 0 to Loader.Modules.Count - 1 do
      Writeln(I + 1, ': ', IntToHex(Loader.Modules[I].ImageBase, 1), ' ', Loader.Modules[I].ImagePath);
  finally
    Loader.Free;
  end;
end.
