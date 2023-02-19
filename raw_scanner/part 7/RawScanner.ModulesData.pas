﻿unit RawScanner.ModulesData;

interface

uses
  Windows,
  Classes,
  SysUtils,
  Math,
  Generics.Collections,
  RawScanner.ApiSet,
  RawScanner.Types,
  RawScanner.Utils;

  {-$DEFINE IGNORE_RELOCATIONS}

type
  // Информация о записи в таблице импорта полученая из RAW модуля
  TImportChunk = record
    Delayed: Boolean;
    OrigLibraryName,
    LibraryName,
    FuncName: string;
    Ordinal: Word;
    ImportTableVA: ULONG_PTR64;       // VA адрес где должна находиться правильная запись
    function ToString: string;
    case Boolean of
      True: ( // доп данные для отложеного импорта
        DelayedIATData: ULONG_PTR64;  // RVA адрес или указатель на отложеную функцию
      );
  end;

  // Информация об экспортируемой функции полученая из RAW модуля
  TExportChunk = record
    FuncName: string;
    Ordinal: Word;
    ExportTableVA: ULONG_PTR64;       // VA адрес в таблице экспорта с RVA линком на адрес функции
    ExportTableRaw: DWORD;            // Оффсет на запись в таблице экспорта в RAW файле
    FuncAddrRVA: DWORD;               // RVA адрес функции, именно он записан по смещению ExportTableVA
    FuncAddrVA: ULONG_PTR64;          // VA адрес функции в адресном пространстве процесса
    FuncAddrRaw: DWORD;               // Оффсет функции в RAW файле
    // если функция перенаправлена, запоминаем куда должно идти перенаправление
    OriginalForvardedTo,              // изначальная строка перенаправления
    ForvardedTo: string;              // преобразованная строка через ApiSet
    function ToString: string;
  end;

  // информация о точках входа и TLS каллбэках
  TEntryPointChunk = record
    EntryPointName: string;
    AddrRaw: DWORD;
    AddrVA: ULONG_PTR64;
  end;

  TDirectoryData = record
    VirtualAddress: ULONG_PTR64;
    Size: DWORD;
  end;

  PImageBaseRelocation = ^TImageBaseRelocation;
  TImageBaseRelocation = record
    VirtualAddress: DWORD;
    SizeOfBlock: DWORD;
  end;

  TRawPEImage = class
  private const
    DEFAULT_FILE_ALIGNMENT = $200;
    DEFAULT_SECTION_ALIGNMENT = $1000;
  private type
    TSectionData = record
      Index: Integer;
      StartRVA, Size: DWORD;
    end;
  strict private
    FDelayDir: TDirectoryData;
    FIndex: Integer;
    FILOnly: Boolean;
    FImageBase: ULONG_PTR64;
    FImagePath: string;
    FImage64: Boolean;
    FImageName, FOriginalName: string;
    FImport: TList<TImportChunk>;
    FImportDir: TDirectoryData;
    FImportAddressTable: TDirectoryData;
    FEntryPoint: ULONG_PTR64;
    FEntryPoints: TList<TEntryPointChunk>;
    FExport: TList<TExportChunk>;
    FExportDir: TDirectoryData;
    FExportIndex: TDictionary<string, Integer>;
    FExportOrdinalIndex: TDictionary<Word, Integer>;
    FNtHeader: TImageNtHeaders64;
    FRebased: Boolean;
    FRedirected: Boolean;
    FRelocationDelta: ULONG_PTR64;
    FRelocations: TList;
    FSections: array of TImageSectionHeader;
    FSizeOfFileImage: Int64;
    FVirtualSizeOfImage: Int64;
    function AlignDown(Value: DWORD; Align: DWORD): DWORD;
    function AlignUp(Value: DWORD; Align: DWORD): DWORD;
    function DirectoryIndexFromRva(RvaAddr: DWORD): Integer;
    function GetSectionData(RvaAddr: DWORD; var Data: TSectionData): Boolean;
    procedure InitDirectories;
    procedure InternalProcessApiSetRedirect(
      const LibName: string; var RedirectTo: string);
    function IsExportForvarded(RvaAddr: DWORD): Boolean;
    procedure LoadFromImage;
    function LoadNtHeader(Raw: TStream): Boolean;
    function LoadSections(Raw: TStream): Boolean;
    function LoadCor20Header(Raw: TStream): Boolean;
    function LoadExport(Raw: TStream): Boolean;
    function LoadImport(Raw: TStream): Boolean;
    function LoadDelayImport(Raw: TStream): Boolean;
    function LoadRelocations(Raw: TStream): Boolean;
    procedure ProcessApiSetRedirect(const LibName: string;
      var ImportChunk: TImportChunk); overload;
    procedure ProcessApiSetRedirect(const LibName: string;
      var ExportChunk: TExportChunk); overload;
    function RvaToRaw(RvaAddr: DWORD): DWORD;
    function RvaToVa(RvaAddr: DWORD): ULONG_PTR64;
    function VaToRaw(VaAddr: ULONG_PTR64): DWORD;
    function VaToRva(VaAddr: ULONG_PTR64): DWORD;
  public
    constructor Create(const ImagePath: string; ImageBase: ULONG_PTR64); overload;
    constructor Create(const ModuleData: TModuleData; AModuleIndex: Integer); overload;
    destructor Destroy; override;
    function ExportIndex(const FuncName: string): Integer; overload;
    function ExportIndex(Ordinal: Word): Integer; overload;
    function GetImageAtAddr(AddrVA: ULONG_PTR64): TRawPEImage;
    procedure ProcessRelocations(AStream: TStream);
    property ComPlusILOnly: Boolean read FILOnly;
    property DelayImportDirectory: TDirectoryData read FDelayDir;
    property EntryPoint: ULONG_PTR64 read FEntryPoint;
    property EntryPointList: TList<TEntryPointChunk> read FEntryPoints;
    property ExportList: TList<TExportChunk> read FExport;
    property ExportDirectory: TDirectoryData read FExportDir;
    property Image64: Boolean read FImage64;
    property ImageBase: ULONG_PTR64 read FImageBase;
    property ImageName: string read FImageName;
    property ImagePath: string read FImagePath;
    property ImportList: TList<TImportChunk> read FImport;
    property ImportAddressTable: TDirectoryData read FImportAddressTable;
    property ImportDirectory: TDirectoryData read FImportDir;
    property ModuleIndex: Integer read FIndex;
    property NtHeader: TImageNtHeaders64 read FNtHeader;
    property OriginalName: string read FOriginalName;
    property Rebased: Boolean read FRebased;
    property Redirected: Boolean read FRedirected;
    property VirtualSizeOfImage: Int64 read FVirtualSizeOfImage;
  end;

  TRawModules = class
  private
    FItems: TObjectList<TRawPEImage>;
    FIndex: TDictionary<string, Integer>;
    FImageBaseIndex: TDictionary<ULONG_PTR64, Integer>;
    function GetRelocatedImage(const LibraryName: string; Is64: Boolean;
      CheckAddrVA: ULONG_PTR64): TRawPEImage;
    function ToKey(const LibraryName: string; Is64: Boolean): string;
  public
    constructor Create;
    destructor Destroy; override;
    function AddImage(const AModule: TModuleData): Integer;
    procedure Clear;
    function GetModule(AddrVa: ULONG_PTR64): Integer;
    function GetProcData(const LibraryName, FuncName: string; Is64: Boolean;
      var ProcData: TExportChunk; CheckAddrVA: ULONG_PTR64): Boolean; overload;
    function GetProcData(const LibraryName: string; Ordinal: Word;
      Is64: Boolean; var ProcData: TExportChunk; CheckAddrVA: ULONG_PTR64): Boolean; overload;
    function GetProcData(const ForvardedFuncName: string; Is64: Boolean;
      var ProcData: TExportChunk; CheckAddrVA: ULONG_PTR64): Boolean; overload;
    property Items: TObjectList<TRawPEImage> read FItems;
  end;

implementation

function ReadString(AStream: TStream): string;
var
  AChar: AnsiChar;
  AString: AnsiString;
begin
  if AStream is TMemoryStream then
  begin
    AString := PAnsiChar(PByte(TMemoryStream(AStream).Memory) +
      AStream.Position);
    AStream.Position := AStream.Position + Length(AString) + 1;
  end
  else
  begin
    AString := '';
    while AStream.Read(AChar, 1) = 1 do
    begin
      if AChar = #0 then
        Break;
      AString := AString + AChar;
    end;
  end;
  Result := string(AString);
end;

function ParceForvardedLink(const Value: string; var LibraryName,
  FuncName: string): Boolean;
var
  Index: Integer;
begin
  // нужно искать именно последнюю точку. если делать через Pos, то на таком
  // форварде "KERNEL.APPCORE.IsDeveloperModeEnabled" в библиотеку уйдет только
  // "KERNEL", а должен "KERNEL.APPCORE"
  Index := Value.LastDelimiter(['.']) + 1;
  Result := Index > 0;
  if not Result then Exit;
  LibraryName := Copy(Value.ToLower, 1, Index) + 'dll';
  FuncName := Copy(Value, Index + 1, Length(Value));
end;

{ TImportChunk }

function TImportChunk.ToString: string;
begin
  Result := ChangeFileExt(LibraryName.ToLower, '.');
  if FuncName = EmptyStr then
    Result := Result + IntToStr(Ordinal)
  else
    Result := Result + UnDecorateSymbolName(FuncName);
  if OrigLibraryName <> EmptyStr then
    Result := OrigLibraryName + Arrow + Result;
end;

{ TExportChunk }

function TExportChunk.ToString: string;
begin
  if FuncName = EmptyStr then
    Result := '#' + IntToStr(Ordinal)
  else
    Result := UnDecorateSymbolName(FuncName);
end;

{ TRawPEImage }

function TRawPEImage.AlignDown(Value, Align: DWORD): DWORD;
begin
  Result := Value and not DWORD(Align - 1);
end;

function TRawPEImage.AlignUp(Value, Align: DWORD): DWORD;
begin
  if Value = 0 then Exit(0);
  Result := AlignDown(Value - 1, Align) + Align;
end;

constructor TRawPEImage.Create(const ModuleData: TModuleData;
  AModuleIndex: Integer);
begin
  FRebased := not ModuleData.IsBaseValid;
  FRedirected := ModuleData.IsRedirected;
  FIndex := AModuleIndex;
  Create(ModuleData.ImagePath, ModuleData.ImageBase);
end;

constructor TRawPEImage.Create(const ImagePath: string; ImageBase: ULONG_PTR64);
begin
  FImagePath := ImagePath;
  FImageBase := ImageBase;
  FImageName := ExtractFileName(ImagePath);
  FImport := TList<TImportChunk>.Create;
  FExport := TList<TExportChunk>.Create;
  FExportIndex := TDictionary<string, Integer>.Create;
  FExportOrdinalIndex := TDictionary<Word, Integer>.Create;
  FEntryPoints := TList<TEntryPointChunk>.Create;
  FRelocations := TList.Create;
  LoadFromImage;
end;

destructor TRawPEImage.Destroy;
begin
  FRelocations.Free;
  FEntryPoints.Free;
  FExportIndex.Free;
  FExportOrdinalIndex.Free;
  FImport.Free;
  FExport.Free;
  inherited;
end;

function TRawPEImage.DirectoryIndexFromRva(RvaAddr: DWORD): Integer;
begin
  Result := -1;
  for var I := 0 to FNtHeader.OptionalHeader.NumberOfRvaAndSizes - 1 do
    if RvaAddr >= FNtHeader.OptionalHeader.DataDirectory[I].VirtualAddress then
      if RvaAddr < FNtHeader.OptionalHeader.DataDirectory[I].VirtualAddress +
        FNtHeader.OptionalHeader.DataDirectory[I].Size then
        Exit(I);
end;

function TRawPEImage.ExportIndex(Ordinal: Word): Integer;
begin
  if not FExportOrdinalIndex.TryGetValue(Ordinal, Result) then
    Result := -1;
end;

function TRawPEImage.ExportIndex(const FuncName: string): Integer;
begin
  if not FExportIndex.TryGetValue(FuncName, Result) then
    Result := -1;
end;

function TRawPEImage.GetImageAtAddr(AddrVA: ULONG_PTR64): TRawPEImage;
begin
  Result := Self;
end;

function TRawPEImage.GetSectionData(RvaAddr: DWORD;
  var Data: TSectionData): Boolean;
var
  I, NumberOfSections: Integer;
  SizeOfRawData, VirtualSize: DWORD;
begin
  Result := False;

  NumberOfSections := Length(FSections);
  for I := 0 to NumberOfSections - 1 do
  begin

    if FSections[I].SizeOfRawData = 0 then
      Continue;
    if FSections[I].PointerToRawData = 0 then
      Continue;

    Data.StartRVA := FSections[I].VirtualAddress;
    if FNtHeader.OptionalHeader.SectionAlignment >= DEFAULT_SECTION_ALIGNMENT then
      Data.StartRVA := AlignDown(Data.StartRVA, FNtHeader.OptionalHeader.SectionAlignment);

    SizeOfRawData := FSections[I].SizeOfRawData;
    VirtualSize := FSections[I].Misc.VirtualSize;

    // если виртуальный размер секции не указан, то берем его из размера данных
    // (см. LdrpSnapIAT или RelocateLoaderSections)
    // к которому уже применяется SectionAlignment
    if VirtualSize = 0 then
      VirtualSize := SizeOfRawData;

    if FNtHeader.OptionalHeader.SectionAlignment >= DEFAULT_SECTION_ALIGNMENT then
    begin
      SizeOfRawData := AlignUp(SizeOfRawData, FNtHeader.OptionalHeader.FileAlignment);
      VirtualSize := AlignUp(VirtualSize, FNtHeader.OptionalHeader.SectionAlignment);
    end;
    Data.Size := Min(SizeOfRawData, VirtualSize);

    if (RvaAddr >= Data.StartRVA) and (RvaAddr < Data.StartRVA + Data.Size) then
    begin
      Data.Index := I;
      Result := True;
      Break;
    end;

  end;
end;

procedure TRawPEImage.InitDirectories;
begin
  with FNtHeader.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT] do
  begin
    FImportAddressTable.VirtualAddress := RvaToVa(VirtualAddress);
    FImportAddressTable.Size := Size;
  end;

  with FNtHeader.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT] do
  begin
    FImportDir.VirtualAddress := RvaToVa(VirtualAddress);
    FImportDir.Size := Size;
  end;

  with FNtHeader.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT] do
  begin
    FDelayDir.VirtualAddress := RvaToVa(VirtualAddress);
    FDelayDir.Size := Size;
  end;

  with FNtHeader.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT] do
  begin
    FExportDir.VirtualAddress := RvaToVa(VirtualAddress);
    FExportDir.Size := Size;
  end;
end;

procedure TRawPEImage.InternalProcessApiSetRedirect(const LibName: string;
  var RedirectTo: string);
var
  ForvardLibraryName, FuncName: string;
begin
  // тут обрабатываем перенаправление системных библиотек через ApiSet
  if not ParceForvardedLink(RedirectTo, ForvardLibraryName, FuncName) then
    Exit;
  ForvardLibraryName := ChangeFileExt(ForvardLibraryName, '');
  if ApiSetRedirector.SchemaPresent(LibName, ForvardLibraryName) then
    RedirectTo := ChangeFileExt(ForvardLibraryName, '.') + FuncName;
end;

function TRawPEImage.IsExportForvarded(RvaAddr: DWORD): Boolean;
begin
  // перенаправленые функции в качестве адреса содержат указатель на
  // строку перенаправления обычно размещенную в директории экспорта
  Result := DirectoryIndexFromRva(RvaAddr) = IMAGE_DIRECTORY_ENTRY_EXPORT;
end;

function TRawPEImage.LoadCor20Header(Raw: TStream): Boolean;
const
  // Version flags for image.
  COR_VERSION_MAJOR_V2 = 2;
  // Header entry point flags.
  COMIMAGE_FLAGS_ILONLY = 1;
  COMIMAGE_FLAGS_32BITREQUIRED = 2;
type
  // COM+ 2.0 header structure.
  PIMAGE_COR20_HEADER = ^IMAGE_COR20_HEADER;
  IMAGE_COR20_HEADER = record
    // Header versioning
    cb: DWORD;
    MajorRuntimeVersion: Word;
    MinorRuntimeVersion: Word;

    // Symbol table and startup information
    MetaData: IMAGE_DATA_DIRECTORY;
    Flags: DWORD;
    EntryPointToken: DWORD;

    // Binding information
    Resources: IMAGE_DATA_DIRECTORY;
    StrongNameSignature: IMAGE_DATA_DIRECTORY;

    // Regular fixup and binding information
    CodeManagerTable: IMAGE_DATA_DIRECTORY;
    VTableFixups: IMAGE_DATA_DIRECTORY;
    ExportAddressTableJumps: IMAGE_DATA_DIRECTORY;

    // Precompiled image info (internal use only - set to zero)
    ManagedNativeHeader: IMAGE_DATA_DIRECTORY;
  end;
var
  ComHeader: IMAGE_COR20_HEADER;
begin
  Result := False;
  with FNtHeader.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR] do
  begin
    if VirtualAddress = 0 then Exit;
    if Size = 0 then Exit;
    Raw.Position := RvaToRaw(VirtualAddress);
  end;
  if Raw.Position = 0 then Exit;
  Raw.ReadBuffer(ComHeader, SizeOf(IMAGE_COR20_HEADER));
  if ComHeader.cb = SizeOf(IMAGE_COR20_HEADER) then
    FILOnly := ComHeader.Flags and (COMIMAGE_FLAGS_ILONLY or COMIMAGE_FLAGS_32BITREQUIRED) <> 0;
end;

function TRawPEImage.LoadDelayImport(Raw: TStream): Boolean;
type
  // https://learn.microsoft.com/ru-ru/cpp/build/reference/understanding-the-helper-function?view=msvc-160#structure-and-constant-definitions
  TImgDelayDescr = record
    grAttrs,                // attributes
    rvaDLLName,             // RVA to dll name
    rvaHmod,                // RVA of module handle
    rvaIAT,                 // RVA of the IAT
    rvaINT,                 // RVA of the INT
    rvaBoundIAT,            // RVA of the optional bound IAT
    rvaUnloadIAT,           // RVA of optional copy of original IAT
    dwTimeStamp: DWORD;     // 0 if not bound,
                            // O.W. date/time stamp of DLL bound to (Old BIND)
  end;

var
  DelayDescr: TImgDelayDescr;

  function GetRva(Value: ULONG_PTR64): ULONG_PTR64;
  const
    dlattrRva = 1;
  begin
    if DelayDescr.grAttrs = dlattrRva then
      Result := Value
    else
      Result := Value - NtHeader.OptionalHeader.ImageBase;
  end;

var
  NextDescriptorRawAddr, LastOffset: Int64;
  IAT, INT, IntData, OrdinalFlag: UInt64;
  DataSize: Integer;
  ImportChunk: TImportChunk;
begin
  Result := False;
  Raw.Position := VaToRaw(DelayImportDirectory.VirtualAddress);
  if Raw.Position = 0 then Exit;

  IntData := 0;
  DataSize := IfThen(Image64, 8, 4);
  ZeroMemory(@ImportChunk, SizeOf(TImportChunk));
  ImportChunk.Delayed := True;
  OrdinalFlag := IfThen(Image64, IMAGE_ORDINAL_FLAG64, IMAGE_ORDINAL_FLAG32);

  Raw.ReadBuffer(DelayDescr, SizeOf(TImgDelayDescr));
  while DelayDescr.rvaIAT <> 0 do
  begin
    // запоминаем адрес следующего дексриптора
    NextDescriptorRawAddr := Raw.Position;

    // вычитываем имя библиотеки импорт из которой описывает дескриптор
    Raw.Position := RvaToRaw(GetRva(DelayDescr.rvaDLLName));
    if Raw.Position = 0 then Exit;

    // контроль перенаправления через ApiSet
    ImportChunk.OrigLibraryName := ReadString(Raw);
    ProcessApiSetRedirect(ImageName, ImportChunk);

    // запоминаем начальне позиции таблицы импорта
    IAT := GetRva(DelayDescr.rvaIAT);
    // таблицы имен
    INT := GetRva(DelayDescr.rvaINT);
    repeat

      // вычитываем имя функции отложеного вызова
      LastOffset := RvaToRaw(INT);
      if LastOffset = 0 then Exit;
      Raw.Position := LastOffset;
      Raw.ReadBuffer(IntData, DataSize);

      if IntData <> 0 then
      begin

        // проверка - идет импорт только по ORDINAL или есть имя функции?
        if IntData and OrdinalFlag = 0 then
        begin
          // имя есть - нужно его вытащить
          Raw.Position := RvaToRaw(GetRva(IntData));
          if Raw.Position = 0 then Exit;
          Raw.ReadBuffer(ImportChunk.Ordinal, SizeOf(Word));
          ImportChunk.FuncName := ReadString(Raw);
        end
        else
        begin
          // имени нет - запоминаем только ordinal функции
          ImportChunk.FuncName := EmptyStr;
          ImportChunk.Ordinal := IntData and not OrdinalFlag;
        end;

        // запоминаем адрес по которому будут располагаться адреса
        // заполняемые лоадером при загрузке модуля в память процесса
        ImportChunk.ImportTableVA := RvaToVa(IAT);

        // запоминаем реальное неинициализированное значение
        // по адресу ImportTableVA будет либо оно, либо адрес вызываемой функции
        // адрес появится после её первого вызова, причем пропадет после выгрузки
        // модуля из адресного пространства процесса, откатившись на старые данные,
        // которые все это время будут хранится в pUnloadIAT (она инициализируется лоадером)
        Raw.Position := VaToRaw(ImportChunk.ImportTableVA);
        if Raw.Position = 0 then Exit;
        Raw.ReadBuffer(ImportChunk.DelayedIATData, DataSize);

        FImport.Add(ImportChunk);
        Inc(IAT, DataSize);
        Inc(INT, DataSize);
      end;

    until IntData = 0;

    // переходим к следующему дескриптору
    Raw.Position := NextDescriptorRawAddr;
    Raw.ReadBuffer(DelayDescr, SizeOf(TImgDelayDescr));
  end;
end;

function TRawPEImage.LoadExport(Raw: TStream): Boolean;
var
  I, Index: Integer;
  LastOffset: Int64;
  ImageExportDirectory: TImageExportDirectory;
  FunctionsAddr, NamesAddr: array of DWORD;
  Ordinals: array of Word;
  ExportChunk: TExportChunk;
begin
  Result := False;
  LastOffset := VaToRaw(ExportDirectory.VirtualAddress);
  if LastOffset = 0 then Exit;
  Raw.Position := LastOffset;
  Raw.ReadBuffer(ImageExportDirectory, SizeOf(TImageExportDirectory));

  if ImageExportDirectory.NumberOfFunctions = 0 then Exit;

  // читаем префикс для перенаправления через ApiSet,
  // он не обязательно будет равен имени библиотеки
  // например:
  // kernel.appcore.dll -> appcore.dll
  // gds32.dll -> fbclient.dll
  Raw.Position := RvaToRaw(ImageExportDirectory.Name);
  if Raw.Position = 0 then
    Exit;
  FOriginalName := ReadString(Raw);

  // читаем массив Rva адресов функций
  SetLength(FunctionsAddr, ImageExportDirectory.NumberOfFunctions);
  Raw.Position := RvaToRaw(ImageExportDirectory.AddressOfFunctions);
  if Raw.Position = 0 then
    Exit;
  Raw.ReadBuffer(FunctionsAddr[0], ImageExportDirectory.NumberOfFunctions shl 2);

  // Важный момент!
  // Библиотека может вообще не иметь функций экспортируемых по имени,
  // только по ординалам. Пример такой библиотеки: mfperfhelper.dll
  // Поэтому нужно делать проверку на их наличие
  if ImageExportDirectory.NumberOfNames > 0 then
  begin

    // читаем массив Rva адресов имен функций
    SetLength(NamesAddr, ImageExportDirectory.NumberOfNames);
    Raw.Position := RvaToRaw(ImageExportDirectory.AddressOfNames);
    if Raw.Position = 0 then
      Exit;
    Raw.ReadBuffer(NamesAddr[0], ImageExportDirectory.NumberOfNames shl 2);

    // читаем массив ординалов - индексов через которые имена функций
    // связываются с массивом адресов
    SetLength(Ordinals, ImageExportDirectory.NumberOfNames);
    Raw.Position := RvaToRaw(ImageExportDirectory.AddressOfNameOrdinals);
    if Raw.Position = 0 then
      Exit;
    Raw.ReadBuffer(Ordinals[0], ImageExportDirectory.NumberOfNames shl 1);

    // сначала обрабатываем функции экспортируемые по имени
    for I := 0 to ImageExportDirectory.NumberOfNames - 1 do
    begin
      Raw.Position := RvaToRaw(NamesAddr[I]);
      if Raw.Position = 0 then Continue;

      // два параметра по которым будем искать фактические данные функции
      ExportChunk.FuncName := ReadString(Raw);
      ExportChunk.Ordinal := Ordinals[I];

      // VA адрес в котором должен лежать Rva линк на адрес функции
      // именно его изменяют при перехвате функции методом патча
      // таблицы экспорта
      ExportChunk.ExportTableVA := RvaToVa(
        ImageExportDirectory.AddressOfFunctions + ExportChunk.Ordinal shl 2);

      // Смещение в RAW файле по которому лежит Rva линк
      ExportChunk.ExportTableRaw := VaToRaw(ExportChunk.ExportTableVA);

      // Само RVA значение которое будут подменять
      ExportChunk.FuncAddrRVA := FunctionsAddr[ExportChunk.Ordinal];

      // VA адрес функции, именно по этому адресу (как правило) устанавливают
      // перехватчик методом сплайсинга или хотпатча через трамплин
      ExportChunk.FuncAddrVA := RvaToVa(ExportChunk.FuncAddrRVA);

      // Raw адрес функции в образе бинарника с которым будет идти проверка
      // на измененые инструкции
      ExportChunk.FuncAddrRaw := RvaToRaw(ExportChunk.FuncAddrRVA);

      {$IFNDEF DISABLE_FORWARD_PROCESSING}
      // обязательная проверка на перенаправление
      // если обрабатывается Forvarded функция то её Rva линк будет указывать
      // на строку, расположеную (как правило) в директории экспорта
      // указывающую какая функция должна быть выполнена вместо перенаправленой
      if IsExportForvarded(FunctionsAddr[ExportChunk.Ordinal]) then
      begin
        Raw.Position := ExportChunk.FuncAddrRaw;
        if Raw.Position = 0 then Continue;
        ExportChunk.OriginalForvardedTo := ReadString(Raw);
        ProcessApiSetRedirect(FOriginalName, ExportChunk);
      end
      else
      begin
        ExportChunk.OriginalForvardedTo := EmptyStr;
        ExportChunk.ForvardedTo := EmptyStr;
      end;
      {$ENDIF}

      // вставляем признак что функция обработана
      FunctionsAddr[ExportChunk.Ordinal] := 0;

      // переводим в NameOrdinal который прописан в таблице импорта
      Inc(ExportChunk.Ordinal, ImageExportDirectory.Base);

      // добавляем в общий список для анализа снаружи
      Index := FExport.Add(ExportChunk);

      // vcl270.bpl спокойно декларирует 4 одинаковых функции
      // вот эти '@$xp$39System@%TArray__1$p17System@TMetaClass%'
      // с ординалами 7341, 7384, 7411, 7222
      // поэтому придется в массиве имен запоминать только самую первую
      // ибо линковаться они могут только через ординалы
      // upd: а они даже не линкуются, а являются дженериками с линком на класс
      // а в таблице экспорта полученном через Symbols присутствует только одна
      // с ординалом 7384
      FExportIndex.TryAdd(ExportChunk.FuncName, Index);

      // индекс для поиска по ординалу
      // (если тут упадет с дубликатом, значит что-то не верно зачитано)
      FExportOrdinalIndex.Add(ExportChunk.Ordinal, Index);
    end;
  end;

  // обработка функций экспортирующихся по индексу
  for I := 0 to ImageExportDirectory.NumberOfFunctions - 1 do
    if FunctionsAddr[I] <> 0 then
    begin
      // здесь все тоже самое за исключение что у функции нет имени
      // и её подгрузка осуществляется по её ординалу, который рассчитывается
      // от базы директории экспорта
      ExportChunk.FuncAddrRVA := FunctionsAddr[I];
      ExportChunk.Ordinal := ImageExportDirectory.Base + DWORD(I);
      ExportChunk.FuncName := EmptyStr;

      // сами значения рассчитываются как есть, без пересчета в ординал
      ExportChunk.ExportTableVA := RvaToVa(
        ImageExportDirectory.AddressOfFunctions + DWORD(I shl 2));

      ExportChunk.FuncAddrVA := RvaToVa(ExportChunk.FuncAddrRVA);
      ExportChunk.FuncAddrRaw := RvaToRaw(ExportChunk.FuncAddrRVA);

      {$IFNDEF DISABLE_FORWARD_PROCESSING}
      if IsExportForvarded(ExportChunk.FuncAddrRVA) then
      begin
        Raw.Position := ExportChunk.FuncAddrRaw;
        if Raw.Position = 0 then Continue;
        ExportChunk.OriginalForvardedTo := ReadString(Raw);
        ProcessApiSetRedirect(FOriginalName, ExportChunk);
      end
      else
      begin
        ExportChunk.OriginalForvardedTo := EmptyStr;
        ExportChunk.ForvardedTo := EmptyStr;
      end;
      {$ENDIF}

      // добавляем в общий список для анализа снаружи
      Index := FExport.Add(ExportChunk);

      // имени нет, поэтому добавляем только в индекс ординалов
      FExportOrdinalIndex.Add(ExportChunk.Ordinal, Index);
    end;

  Result := True;
end;

procedure TRawPEImage.LoadFromImage;
var
  Raw: TMemoryStream;
  IDH: TImageDosHeader;
  Chunk: TEntryPointChunk;
begin
  Raw := TMemoryStream.Create;
  try
    Raw.LoadFromFile(FImagePath);
    FSizeOfFileImage := Raw.Size;

    // проверка DOS заголовка
    Raw.ReadBuffer(IDH, SizeOf(TImageDosHeader));
    if IDH.e_magic <> IMAGE_DOS_SIGNATURE then
      Exit;
    Raw.Position := IDH._lfanew;

    // загрузка NT заголовка, всегда в виде 64 битной структуры
    // даже если библиотека 32 бита
    if not LoadNtHeader(Raw) then Exit;

    // читаем массив секций, они нужны для работы алигнов в RvaToRaw
    if not LoadSections(Raw) then Exit;

    // теперь можем инициализировать параметры точки входа
    if NtHeader.OptionalHeader.AddressOfEntryPoint <> 0 then
    begin
      FEntryPoint := RvaToVa(NtHeader.OptionalHeader.AddressOfEntryPoint);
      Chunk.EntryPointName := 'EntryPoint';
      Chunk.AddrRaw := VaToRaw(FEntryPoint);
      Chunk.AddrVA := FEntryPoint;
      FEntryPoints.Add(Chunk);
    end;

    // читаем COM+ заголовок (если есть)
    LoadCor20Header(Raw);

    // в принципе, если файл не исполняемый COM+, уже тут можно выходить
    // но для проверки, оставим инициализацию всех данных.

    // инициализируем адреса таблиц импорта и экспорта
    // они пригодятся снаружи для ускорения проверки этих таблиц
    InitDirectories;

    // читаем директорию экспорта
    LoadExport(Raw);

    // читаем дескрипторы импорта
    LoadImport(Raw);

    // дескрипторы отложеного импорта содержат данные с учетом релокейшенов
    // для чтения правильных значений нужно сделать правки
    {$IFNDEF IGNORE_RELOCATIONS}
    if LoadRelocations(Raw) then
      ProcessRelocations(Raw);
    {$ENDIF}

    // читаем дескрипторы отложеного импорта
    LoadDelayImport(Raw);

  finally
    Raw.Free;
  end;
end;

function TRawPEImage.LoadImport(Raw: TStream): Boolean;
var
  ImageImportDescriptor: TImageImportDescriptor;
  NextDescriptorRawAddr, LastOffset: Int64;
  IatData, OrdinalFlag, OriginalFirstThunk: UInt64;
  IatDataSize: Integer;
  ImportChunk: TImportChunk;
begin
  Result := False;
  Raw.Position := VaToRaw(FImportDir.VirtualAddress);
  if Raw.Position = 0 then Exit;

  ZeroMemory(@ImportChunk, SizeOf(TImportChunk));
  while (Raw.Read(ImageImportDescriptor, SizeOf(TImageImportDescriptor)) =
    SizeOf(TImageImportDescriptor)) and (ImageImportDescriptor.OriginalFirstThunk <> 0) do
  begin

    // запоминаем адрес следующего дексриптора
    NextDescriptorRawAddr := Raw.Position;

    // вычитываем имя библиотеки импорт из которой описывает дескриптор
    Raw.Position := RvaToRaw(ImageImportDescriptor.Name);
    if Raw.Position = 0 then
      Exit;

    // контроль перенаправления через ApiSet
    ImportChunk.OrigLibraryName := ReadString(Raw);
    ProcessApiSetRedirect(ImageName, ImportChunk);

    // инициализируем размер записей и флаги
    IatDataSize := IfThen(Image64, 8, 4);
    OrdinalFlag := IfThen(Image64, IMAGE_ORDINAL_FLAG64, IMAGE_ORDINAL_FLAG32);

    // вычитываем все записи описываемые дескриптором, пока не кончатся
    IatData := 0;
    // сразу запоминаем адрес таблицы в которой будут располазаться адреса
    // заполняемые лоадером при загрузке модуля в память процесса
    ImportChunk.ImportTableVA := RvaToVa(ImageImportDescriptor.FirstThunk);
    // но вычитывать будем из таблицы через OriginalFirstThunk
    // т.к. FirstThunk в Raw файле может содержать привязаные данные (реальные адреса)
    // которые для 64 бит мало того, что могут быть далеко за пределами DWORD
    // так еще и не подойдут для RvaToRaw
    // пример такой ситуации "ntoskrnl.exe"
    OriginalFirstThunk := RvaToVa(ImageImportDescriptor.OriginalFirstThunk);
    // правда OriginalFirstThunk может и не быть в некоторых случаях
    // в таком случае чтение будет идти из FirstThunk
    if OriginalFirstThunk = 0 then
      OriginalFirstThunk := ImportChunk.ImportTableVA;
    repeat

      LastOffset := VaToRaw(OriginalFirstThunk);
      if LastOffset = 0 then
        Exit;

      Raw.Position := LastOffset;
      Raw.ReadBuffer(IatData, IatDataSize);

      if IatData <> 0 then
      begin
        // проверка - идет импорт только по ORDINAL или есть имя функции?
        if IatData and OrdinalFlag = 0 then
        begin
          // имя есть - нужно его вытащить
          Raw.Position := RvaToRaw(IatData);
          if Raw.Position = 0 then
            Exit;
          Raw.ReadBuffer(ImportChunk.Ordinal, SizeOf(Word));
          ImportChunk.FuncName := ReadString(Raw);
        end
        else
        begin
          // имени нет - запоминаем только ordinal функции
          ImportChunk.FuncName := EmptyStr;
          ImportChunk.Ordinal := IatData and not OrdinalFlag;
        end;

        FImport.Add(ImportChunk);
        Inc(ImportChunk.ImportTableVA, IatDataSize);
        Inc(OriginalFirstThunk, IatDataSize);
      end;
    until IatData = 0;

    // переходим к следующему дескриптору
    Raw.Position := NextDescriptorRawAddr;
  end;

  Result := ImageImportDescriptor.OriginalFirstThunk = 0;
end;

function TRawPEImage.LoadNtHeader(Raw: TStream): Boolean;
var
  ImageOptionalHeader32: TImageOptionalHeader32;
begin
  Result := False;
  Raw.ReadBuffer(FNtHeader, SizeOf(DWORD) + SizeOf(TImageFileHeader));
  if FNtHeader.Signature <> IMAGE_NT_SIGNATURE then Exit;
  if FNtHeader.FileHeader.Machine = IMAGE_FILE_MACHINE_I386 then
  begin
    FImage64 := False;
    Raw.ReadBuffer(ImageOptionalHeader32, SizeOf(TImageOptionalHeader32));
    FNtHeader.OptionalHeader.Magic := ImageOptionalHeader32.Magic;
    FNtHeader.OptionalHeader.MajorLinkerVersion := ImageOptionalHeader32.MajorLinkerVersion;
    FNtHeader.OptionalHeader.MinorLinkerVersion := ImageOptionalHeader32.MinorLinkerVersion;
    FNtHeader.OptionalHeader.SizeOfCode := ImageOptionalHeader32.SizeOfCode;
    FNtHeader.OptionalHeader.SizeOfInitializedData := ImageOptionalHeader32.SizeOfInitializedData;
    FNtHeader.OptionalHeader.SizeOfUninitializedData := ImageOptionalHeader32.SizeOfUninitializedData;
    FNtHeader.OptionalHeader.AddressOfEntryPoint := ImageOptionalHeader32.AddressOfEntryPoint;
    FNtHeader.OptionalHeader.BaseOfCode := ImageOptionalHeader32.BaseOfCode;
    FNtHeader.OptionalHeader.ImageBase := ImageOptionalHeader32.ImageBase;
    FNtHeader.OptionalHeader.SectionAlignment := ImageOptionalHeader32.SectionAlignment;
    FNtHeader.OptionalHeader.FileAlignment := ImageOptionalHeader32.FileAlignment;
    FNtHeader.OptionalHeader.MajorOperatingSystemVersion := ImageOptionalHeader32.MajorOperatingSystemVersion;
    FNtHeader.OptionalHeader.MinorOperatingSystemVersion := ImageOptionalHeader32.MinorOperatingSystemVersion;
    FNtHeader.OptionalHeader.MajorImageVersion := ImageOptionalHeader32.MajorImageVersion;
    FNtHeader.OptionalHeader.MinorImageVersion := ImageOptionalHeader32.MinorImageVersion;
    FNtHeader.OptionalHeader.MajorSubsystemVersion := ImageOptionalHeader32.MajorSubsystemVersion;
    FNtHeader.OptionalHeader.MinorSubsystemVersion := ImageOptionalHeader32.MinorSubsystemVersion;
    FNtHeader.OptionalHeader.Win32VersionValue := ImageOptionalHeader32.Win32VersionValue;
    FNtHeader.OptionalHeader.SizeOfImage := ImageOptionalHeader32.SizeOfImage;
    FNtHeader.OptionalHeader.SizeOfHeaders := ImageOptionalHeader32.SizeOfHeaders;
    FNtHeader.OptionalHeader.CheckSum := ImageOptionalHeader32.CheckSum;
    FNtHeader.OptionalHeader.Subsystem := ImageOptionalHeader32.Subsystem;
    FNtHeader.OptionalHeader.DllCharacteristics := ImageOptionalHeader32.DllCharacteristics;
    FNtHeader.OptionalHeader.SizeOfStackReserve := ImageOptionalHeader32.SizeOfStackReserve;
    FNtHeader.OptionalHeader.SizeOfStackCommit := ImageOptionalHeader32.SizeOfStackCommit;
    FNtHeader.OptionalHeader.SizeOfHeapReserve := ImageOptionalHeader32.SizeOfHeapReserve;
    FNtHeader.OptionalHeader.SizeOfHeapCommit := ImageOptionalHeader32.SizeOfHeapCommit;
    FNtHeader.OptionalHeader.LoaderFlags := ImageOptionalHeader32.LoaderFlags;
    FNtHeader.OptionalHeader.NumberOfRvaAndSizes := ImageOptionalHeader32.NumberOfRvaAndSizes;
    for var I := 0 to IMAGE_NUMBEROF_DIRECTORY_ENTRIES - 1 do
      FNtHeader.OptionalHeader.DataDirectory[I] := ImageOptionalHeader32.DataDirectory[I];
  end
  else
  begin
    FImage64 := True;
    Raw.ReadBuffer(FNtHeader.OptionalHeader, SizeOf(TImageOptionalHeader64));
  end;
  Result := True;
end;

function TRawPEImage.LoadRelocations(Raw: TStream): Boolean;
const
  IMAGE_REL_BASED_ABSOLUTE = 0;
  IMAGE_REL_BASED_HIGHLOW = 3;
  IMAGE_REL_BASED_DIR64 = 10;
var
  Reloc: TImageDataDirectory;
  ImageBaseRelocation: TImageBaseRelocation;
  RelocationBlock: Word;
  MaxPos: NativeInt;
  I: Integer;
begin
  // Проверка, нужно ли чообще подключать таблицу релокаций?
  {$IFDEF DEBUG} {$OVERFLOWCHECKS OFF} {$ENDIF}
  FRelocationDelta := ImageBase - FNtHeader.OptionalHeader.ImageBase;
  {$IFDEF DEBUG} {$OVERFLOWCHECKS ON} {$ENDIF}
  if not Image64 then
    FRelocationDelta := DWORD(FRelocationDelta);
  Result := FRelocationDelta = 0;
  if Result then Exit;
  Reloc := FNtHeader.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
  if (Reloc.VirtualAddress = 0) or (Reloc.Size = 0) then Exit;
  Raw.Position := RvaToRaw(Reloc.VirtualAddress);
  if Raw.Position = 0 then Exit;
  MaxPos := Raw.Position + Reloc.Size;
  while Raw.Position < MaxPos do
  begin
    Raw.ReadBuffer(ImageBaseRelocation, SizeOf(TImageBaseRelocation));
    // SizeOfBlock включает в себя полный размер данных вместе с заголовком
    Dec(ImageBaseRelocation.SizeOfBlock, SizeOf(TImageBaseRelocation));
    for I := 0 to Integer(ImageBaseRelocation.SizeOfBlock shr 1) - 1 do
    begin
      Raw.ReadBuffer(RelocationBlock, SizeOf(Word));
      case RelocationBlock shr 12 of
        IMAGE_REL_BASED_HIGHLOW,
        IMAGE_REL_BASED_DIR64:
          FRelocations.Add(Pointer(RvaToRaw(ImageBaseRelocation.VirtualAddress + RelocationBlock and $FFF)));
        IMAGE_REL_BASED_ABSOLUTE:
          // ABSOLUTE может встретится посередине, а не только в конце,
          // как утверждают некоторые источники.
          // пример такой библиотеки
          // C:\Program Files (x86)\Embarcadero\Studio\21.0\bin\dcc32270.dll
          // поэтому эта запись должна быть пропущена, и она не означает
          // конец списка
          Continue;
      end;
    end;
  end;
  Result := True;
end;

function TRawPEImage.LoadSections(Raw: TStream): Boolean;
begin
  Result := FNtHeader.FileHeader.NumberOfSections > 0;
  SetLength(FSections, FNtHeader.FileHeader.NumberOfSections);
  for var I := 0 to FNtHeader.FileHeader.NumberOfSections - 1 do
  begin
    Raw.ReadBuffer(FSections[I], SizeOf(TImageSectionHeader));
    FVirtualSizeOfImage := Max(FVirtualSizeOfImage,
      FSections[I].VirtualAddress + FSections[I].Misc.VirtualSize);
  end;
end;

procedure TRawPEImage.ProcessApiSetRedirect(const LibName: string;
  var ImportChunk: TImportChunk);
var
  Tmp: string;
begin
  Tmp := ImportChunk.OrigLibraryName;
  InternalProcessApiSetRedirect(LibName, Tmp);
  if Tmp = ImportChunk.OrigLibraryName then
    ImportChunk.OrigLibraryName := EmptyStr
  else
    ImportChunk.OrigLibraryName := ChangeFileExt(ImportChunk.OrigLibraryName, EmptyStr);
  ImportChunk.LibraryName := Tmp;
end;

procedure TRawPEImage.ProcessApiSetRedirect(const LibName: string;
  var ExportChunk: TExportChunk);
var
  Tmp: string;
begin
  Tmp := ExportChunk.OriginalForvardedTo;
  InternalProcessApiSetRedirect(LibName, Tmp);
  if Tmp = ExportChunk.OriginalForvardedTo then
    ExportChunk.OriginalForvardedTo := EmptyStr
  else
    ExportChunk.OriginalForvardedTo := ChangeFileExt(ExportChunk.OriginalForvardedTo, EmptyStr);
  ExportChunk.ForvardedTo := Tmp;
end;

procedure TRawPEImage.ProcessRelocations(AStream: TStream);
var
  AddrSize: Byte;
  Reloc: ULONG_PTR64;
begin
  if FRelocationDelta = 0 then Exit;
  Reloc := 0;
  AddrSize := IfThen(Image64, 8, 4);
  for var RawReloc in FRelocations do
  begin
    AStream.Position := Int64(RawReloc);
    AStream.ReadBuffer(Reloc, AddrSize);
    {$IFDEF DEBUG} {$OVERFLOWCHECKS OFF} {$ENDIF}
    Inc(Reloc, FRelocationDelta);
    {$IFDEF DEBUG} {$OVERFLOWCHECKS ON} {$ENDIF}
    AStream.Position := Int64(RawReloc);
    AStream.WriteBuffer(Reloc, AddrSize);
  end;
end;

function TRawPEImage.RvaToRaw(RvaAddr: DWORD): DWORD;
var
  NumberOfSections: Integer;
  SectionData: TSectionData;
  SizeOfImage: DWORD;
  PointerToRawData: DWORD;
begin
  Result := 0;

  if RvaAddr < FNtHeader.OptionalHeader.SizeOfHeaders then
    Exit(RvaAddr);

  NumberOfSections := Length(FSections);
  if NumberOfSections = 0 then
  begin
    if FNtHeader.OptionalHeader.SectionAlignment >= DEFAULT_SECTION_ALIGNMENT then
      SizeOfImage := AlignUp(FNtHeader.OptionalHeader.SizeOfImage,
        FNtHeader.OptionalHeader.SectionAlignment)
    else
      SizeOfImage := FNtHeader.OptionalHeader.SizeOfImage;
    if RvaAddr < SizeOfImage then
      Exit(RvaAddr);
    Exit;
  end;

  if GetSectionData(RvaAddr, SectionData) then
  begin
    PointerToRawData := FSections[SectionData.Index].PointerToRawData;
    if FNtHeader.OptionalHeader.SectionAlignment >= DEFAULT_SECTION_ALIGNMENT then
      PointerToRawData := AlignDown(PointerToRawData, DEFAULT_FILE_ALIGNMENT);

    Inc(PointerToRawData, RvaAddr - SectionData.StartRVA);

    if PointerToRawData < FSizeOfFileImage then
      Result := PointerToRawData;
  end;
end;

function TRawPEImage.RvaToVa(RvaAddr: DWORD): ULONG_PTR64;
begin
  Result := FImageBase + RvaAddr;
end;

function TRawPEImage.VaToRaw(VaAddr: ULONG_PTR64): DWORD;
begin
  Result := RvaToRaw(VaToRva(VaAddr));
end;

function TRawPEImage.VaToRva(VaAddr: ULONG_PTR64): DWORD;
begin
  Result := VaAddr - FImageBase;
end;

{ TRawModules }

function TRawModules.AddImage(const AModule: TModuleData): Integer;
var
  Key: string;
  AItem: TRawPEImage;
begin
  AItem := TRawPEImage.Create(AModule, FItems.Count);
  Result := FItems.Add(AItem);
  FImageBaseIndex.Add(AModule.ImageBase, Result);
  Key := ToKey(AItem.ImageName, AItem.Image64);
  FIndex.TryAdd(Key, Result);
end;

procedure TRawModules.Clear;
begin
  FItems.Clear;
  FIndex.Clear;
  FImageBaseIndex.Clear;
end;

constructor TRawModules.Create;
begin
  FItems := TObjectList<TRawPEImage>.Create;
  FIndex := TDictionary<string, Integer>.Create;
  FImageBaseIndex := TDictionary<ULONG_PTR64, Integer>.Create;
end;

destructor TRawModules.Destroy;
begin
  FImageBaseIndex.Free;
  FIndex.Free;
  FItems.Free;
  inherited;
end;

function TRawModules.GetModule(AddrVa: ULONG_PTR64): Integer;
begin
  if not FImageBaseIndex.TryGetValue(AddrVa, Result) then
    Result := -1;
end;

function TRawModules.GetProcData(const LibraryName, FuncName: string;
  Is64: Boolean; var ProcData: TExportChunk; CheckAddrVA: ULONG_PTR64): Boolean;
const
  OrdinalPrefix = '#';
var
  Ordinal, Index: Integer;
  Image: TRawPEImage;
begin
  Result := False;
  if LibraryName = EmptyStr then Exit;

  // проверка на импорт по ординалу
  // форвард может идти просто как число, а может с префиксом решетки
  if FuncName = EmptyStr then Exit;
  if ((FuncName[1] = OrdinalPrefix) and
    TryStrToInt(Copy(FuncName, 2, Length(FuncName) - 1), Ordinal)) or
    TryStrToInt(FuncName, Ordinal) then
  begin
    Result := GetProcData(LibraryName, Ordinal, Is64, ProcData, CheckAddrVA);
    if Result then
      Exit;
  end;

  Image := GetRelocatedImage(LibraryName, Is64, CheckAddrVA);
  if Assigned(Image) then
  begin
    Index := Image.ExportIndex(FuncName);
    Result := Index >= 0;
    if Result then
      ProcData := Image.ExportList.List[Index];
  end;
end;

function TRawModules.GetProcData(const ForvardedFuncName: string; Is64: Boolean;
  var ProcData: TExportChunk; CheckAddrVA: ULONG_PTR64): Boolean;
var
  LibraryName, FuncName: string;
begin
  Result := ParceForvardedLink(ForvardedFuncName, LibraryName, FuncName);
  if Result then
    Result := GetProcData(LibraryName, FuncName, Is64, ProcData, CheckAddrVA);

  // форвард может быть множественный, поэтому рефорвардим до упора
  // например:
  // USP10.ScriptGetLogicalWidths ->
  //   GDI32.ScriptGetLogicalWidths ->
  //     gdi32full.ScriptGetLogicalWidths
  if Result and (ProcData.ForvardedTo <> EmptyStr) then
    Result := GetProcData(ProcData.ForvardedTo, Is64, ProcData, CheckAddrVA);
end;

function TRawModules.GetRelocatedImage(const LibraryName: string; Is64: Boolean;
  CheckAddrVA: ULONG_PTR64): TRawPEImage;
var
  Index: Integer;
begin
  // быстрая проверка, есть ли информация о библиотеке?
  if FIndex.TryGetValue(ToKey(LibraryName, Is64), Index) then
    Result := FItems.List[Index].GetImageAtAddr(CheckAddrVA)
  else
    Result := nil;
end;

function TRawModules.GetProcData(const LibraryName: string; Ordinal: Word;
  Is64: Boolean; var ProcData: TExportChunk; CheckAddrVA: ULONG_PTR64): Boolean;
var
  Index: Integer;
  Image: TRawPEImage;
begin
  Result := False;
  Image := GetRelocatedImage(LibraryName, Is64, CheckAddrVA);
  if Assigned(Image) then
  begin
    Index := Image.ExportIndex(Ordinal);
    Result := Index >= 0;
    if Result then
      ProcData := Image.ExportList.List[Index];
  end;
end;

function TRawModules.ToKey(const LibraryName: string; Is64: Boolean): string;
begin
  Result := LowerCase(ExtractFileName(LibraryName) + BoolToStr(Is64));
end;

end.
