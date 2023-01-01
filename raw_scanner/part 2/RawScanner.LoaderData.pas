unit RawScanner.LoaderData;

interface

uses
  Windows,
  SysUtils,
  Classes,
  PsApi,
  RawScanner.Types,
  RawScanner.Wow64,
  RawScanner.Utils;

const
  LDRP_IMAGE_DLL                  = $00000004;
  LDRP_IMAGE_NOT_AT_BASE          = $00200000;
  LDRP_COR_IMAGE                  = $00400000;
  LDRP_REDIRECTED                 = $10000000;

type
  TLoaderData = class
  private
    FProcess: THandle;
    FRootModule: TModuleData;
    FModuleList: TModuleList;
    FUse64Addr: Boolean;
    function Scan32LdrData(LdrAddr: ULONG_PTR64): Integer;
    function Scan64LdrData(LdrAddr: ULONG_PTR64): Integer;
  public
    constructor Create(AProcess: THandle; AUse64Addr: Boolean);
    destructor Destroy; override;
    function Load32LoaderData(LdrAddr: ULONG_PTR64): Integer;
    function Load64LoaderData(LdrAddr: ULONG_PTR64): Integer;
    property RootModule: TModuleData read FRootModule;
    property Modules: TModuleList read FModuleList;
  end;

implementation

type
  LIST_ENTRY32 = record
    FLink, BLink: ULONG;
  end;

  PEB_LDR_DATA32 = record
    Length: ULONG;
    Initialized: BOOL;
    SsHandle: ULONG;
    InLoadOrderModuleList: LIST_ENTRY32;
    InMemoryOrderModuleList: LIST_ENTRY32;
    InInitializationOrderModuleList: LIST_ENTRY32;
    // etc...
  end;

  LDR_DATA_TABLE_ENTRY32 = record
    InLoadOrderLinks: LIST_ENTRY32;
    InMemoryOrderLinks: LIST_ENTRY32;
    InInitializationOrderLinks: LIST_ENTRY32;
    DllBase: ULONG;
    EntryPoint: ULONG;
    SizeOfImage: ULONG;
    FullDllName: UNICODE_STRING32;
    BaseDllName: UNICODE_STRING32;
    Flags: ULONG;
    // etc...
  end;

  LIST_ENTRY64 = record
    FLink, BLink: ULONG_PTR64;
  end;

  PEB_LDR_DATA64 = record
    Length: ULONG;
    Initialized: BOOL;
    SsHandle: ULONG_PTR64;
    InLoadOrderModuleList: LIST_ENTRY64;
    InMemoryOrderModuleList: LIST_ENTRY64;
    InInitializationOrderModuleList: LIST_ENTRY64;
    // etc...
  end;

  LDR_DATA_TABLE_ENTRY64 = record
    InLoadOrderLinks: LIST_ENTRY64;
    InMemoryOrderLinks: LIST_ENTRY64;
    InInitializationOrderLinks: LIST_ENTRY64;
    DllBase: ULONG_PTR64;
    EntryPoint: ULONG_PTR64;
    SizeOfImage: ULONG_PTR64;
    FullDllName: UNICODE_STRING64;
    BaseDllName: UNICODE_STRING64;
    Flags: ULONG;
    // etc...
  end;

function NormalizePath(const Value: string): string;
const
  DriveNameSize = 4;
  VolumeCount = 26;
  DriveTotalSize = DriveNameSize * VolumeCount;
var
  Buff, Volume: string;
  I, Count, dwQueryLength: Integer;
  lpQuery: array [0..MAX_PATH - 1] of Char;
begin
  Result := Value;
  SetLength(Buff, DriveTotalSize);
  Count := GetLogicalDriveStrings(DriveTotalSize, @Buff[1]) div DriveNameSize;
  for I := 0 to Count - 1 do
  begin
    Volume := PChar(@Buff[(I * DriveNameSize) + 1]);
    Volume[3] := #0;
    // Преобразуем имя каждого диска в символьную ссылку и
    // сравниваем с формализированным путем
    QueryDosDevice(PChar(Volume), @lpQuery[0], MAX_PATH);
    dwQueryLength := Length(string(lpQuery));
    if Copy(Result, 1, dwQueryLength) = string(lpQuery) then
    begin
      Volume[3] := '\';
      if lpQuery[dwQueryLength - 1] <> '\' then
        Inc(dwQueryLength);
      Delete(Result, 1, dwQueryLength);
      Result := Volume + Result;
      Break;
    end;
  end;
end;

{ TLoaderData }

constructor TLoaderData.Create(AProcess: THandle; AUse64Addr: Boolean);
begin
  FProcess := AProcess;
  FUse64Addr := AUse64Addr;
  FModuleList := TModuleList.Create;
end;

destructor TLoaderData.Destroy;
begin
  FModuleList.Free;
  inherited;
end;

function TLoaderData.Load32LoaderData(LdrAddr: ULONG_PTR64): Integer;
begin
  if LdrAddr <> 0 then
    Result := Scan32LdrData(LdrAddr)
  else
    Result := 0;
end;

function TLoaderData.Load64LoaderData(LdrAddr: ULONG_PTR64): Integer;
begin
  if LdrAddr <> 0 then
    Result := Scan64LdrData(LdrAddr)
  else
    Result := 0;
end;

function TLoaderData.Scan32LdrData(LdrAddr: ULONG_PTR64): Integer;
const
  MM_HIGHEST_USER_ADDRESS = {$IFDEF WIN32}$7FFEFFFF;{$ELSE}$7FFFFFEFFFF;{$ENDIF}

  function IsFile32(const FilePath: string): Boolean;
  var
    DosHeader: TImageDosHeader;
    NtHeader: TImageNtHeaders32;
    Raw: TBufferedFileStream;
  begin
    Raw := TBufferedFileStream.Create(FilePath, fmShareDenyWrite);
    try
      Raw.ReadBuffer(DosHeader, SizeOf(TImageDosHeader));
      Raw.Position := DosHeader._lfanew;
      Raw.ReadBuffer(NtHeader, SizeOf(TImageNtHeaders32));
      Result := NtHeader.FileHeader.Machine = IMAGE_FILE_MACHINE_I386;
    finally
      Raw.Free;
    end;
  end;

var
  Ldr: PEB_LDR_DATA32;
  Entry: LDR_DATA_TABLE_ENTRY32;
  Module: TModuleData;
  MapedFilePath: string;
  MapedFilePathLen: DWORD;
begin
  Result := 0;

  // читаем первичную структуру для определения начала списка
  if not ReadRemoteMemory(FProcess, LdrAddr,
    @Ldr, SizeOf(PEB_LDR_DATA32)) then
    Exit;

  LdrAddr := Ldr.InLoadOrderModuleList.FLink;

  SetLength(MapedFilePath, MAX_PATH);

  while ReadRemoteMemory(FProcess, LdrAddr,
    @Entry, SizeOf(LDR_DATA_TABLE_ENTRY32)) and (Entry.DllBase <> 0) do
  begin
    Module.ImageBase := Entry.DllBase;
    Module.Is64Image := False;

    SetLength(Module.ImagePath, Entry.FullDllName.Length shr 1);
    if not ReadRemoteMemory(FProcess, Entry.FullDllName.Buffer,
      @Module.ImagePath[1], Entry.FullDllName.Length) then
    begin
      LdrAddr := Entry.InLoadOrderLinks.FLink;
      Continue;
    end;

    // нюанс, 32 битные библиотеки в списке LDR будут прописаны с путем из
    // дефолтной системной директории, хотя на самом деле они грузятся
    // из SysWow64 папки. Поэтому проверяем, если SysWow64 присутствует
    // то все 32 битные пути библиотек меняем на правильный посредством
    // вызова GetMappedFileName + нормализация.
    // Для 64 битных это делать не имеет смысла, т.к. они грузятся по старшим
    // адресам куда не может быть загружена 32 битная библиотека, а по младшим
    // мы и сами сможет прочитать данные из 32 битной сборки
    if FUse64Addr then
    begin
      // GetMappedFileName работает с адресами меньше MM_HIGHEST_USER_ADDRESS
      // если адрес будет больше - вернется ноль с ошибкой ERROR_INVALID_PARAMETER
      if Module.ImageBase < MM_HIGHEST_USER_ADDRESS then
      begin
        MapedFilePathLen := GetMappedFileName(FProcess, Pointer(Module.ImageBase),
          @MapedFilePath[1], MAX_PATH * SizeOf(Char));
        if MapedFilePathLen > 0 then
          Module.ImagePath := NormalizePath(Copy(MapedFilePath, 1, MapedFilePathLen));
      end
      else
      begin
        // а если адрес библиотеки выше допустимого, то будем делать костыль
        // проверка, находится ли файл в системной директории?
        if Module.ImagePath.StartsWith(Wow64Support.SystemDirectory, True) then
        begin
          // проверка, есть ли файл на диске и является ли он 32 битным?
          if not (FileExists(Module.ImagePath) and IsFile32(Module.ImagePath)) then
          begin
            // нет, файл отсутствует либо не является 32 битным
            // меняем путь на SysWow64 директорию
            Module.ImagePath := StringReplace(
              Module.ImagePath,
              Wow64Support.SystemDirectory,
              Wow64Support.SysWow64Directory, [rfIgnoreCase]);
            // повторная проверка
            if not (FileExists(Module.ImagePath) and IsFile32(Module.ImagePath)) then
              // если в SysWow64 нет подходящего файла, чтож - тогда пропускаем его
              // потому что мы его всеравно не сможем правильно подгрузить и обработать
              Module.ImagePath := EmptyStr;
          end;
        end;
      end;
    end;

    // инициализируе дополнительные флаги загруженого модуля
    Module.IsDll := Entry.Flags and LDRP_IMAGE_DLL <> 0;
    Module.IsBaseValid := Entry.Flags and LDRP_IMAGE_NOT_AT_BASE = 0;
    Module.IsILCoreImage := Entry.Flags and LDRP_COR_IMAGE <> 0;
    Module.IsRedirected := Entry.Flags and LDRP_REDIRECTED <> 0;

    if FRootModule.IsEmpty then
     FRootModule := Module
    else
      if FRootModule.ImageBase <> Module.ImageBase then
        FModuleList.Add(Module);

    LdrAddr := Entry.InLoadOrderLinks.FLink;
    Inc(Result);
  end;
end;

function TLoaderData.Scan64LdrData(LdrAddr: ULONG_PTR64): Integer;
var
  Ldr: PEB_LDR_DATA64;
  Entry: LDR_DATA_TABLE_ENTRY64;
  Module: TModuleData;
begin
  Result := 0;

  // читаем первичную структуру для определения начала списка
  if not ReadRemoteMemory(FProcess, LdrAddr,
    @Ldr, SizeOf(PEB_LDR_DATA64)) then
    Exit;

  LdrAddr := Ldr.InLoadOrderModuleList.FLink;

  while (ReadRemoteMemory(FProcess, LdrAddr,
    @Entry, SizeOf(LDR_DATA_TABLE_ENTRY64))) and (Entry.DllBase <> 0) do
  begin
    Module.ImageBase := Entry.DllBase;
    Module.Is64Image := True;
    SetLength(Module.ImagePath, Entry.FullDllName.Length shr 1);
    if not ReadRemoteMemory(FProcess, Entry.FullDllName.Buffer,
      @Module.ImagePath[1], Entry.FullDllName.Length) then
    begin
      LdrAddr := Entry.InLoadOrderLinks.FLink;
      Continue;
    end;

    // инициализируе дополнительные флаги загруженого модуля
    Module.IsDll := Entry.Flags and LDRP_IMAGE_DLL <> 0;
    Module.IsBaseValid := Entry.Flags and LDRP_IMAGE_NOT_AT_BASE = 0;
    Module.IsILCoreImage := Entry.Flags and LDRP_COR_IMAGE <> 0;
    Module.IsRedirected := Entry.Flags and LDRP_REDIRECTED <> 0;

    // есть нюанс, в 64 битном списке 32 битного процесса первым
    // идет запись об исполняемом файле, даже не смотря на то что он 32 битный
    // поэтому делаем проверку - была ли загружена эта информация при чтении
    // 32 битного списка загрузчика?
    if FRootModule.IsEmpty then
     FRootModule := Module
    else
      if FRootModule.ImageBase <> Module.ImageBase then
        FModuleList.Add(Module);

    LdrAddr := Entry.InLoadOrderLinks.FLink;
    Inc(Result);
  end;
end;

end.
