unit RawScanner.ModulesData;

interface

uses
  Windows,
  Classes,
  SysUtils,
  Math,
  Generics.Collections,
  RawScanner.Types,
  RawScanner.Utils;

type
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
    FIndex: Integer;
    FILOnly: Boolean;
    FImageBase: ULONG_PTR64;
    FImagePath: string;
    FImage64: Boolean;
    FImageName, FOriginalName: string;
    FEntryPoint: ULONG_PTR64;
    FEntryPoints: TList<TEntryPointChunk>;
    FExport: TList<TExportChunk>;
    FExportDir: TDirectoryData;
    FExportIndex: TDictionary<string, Integer>;
    FExportOrdinalIndex: TDictionary<Word, Integer>;
    FNtHeader: TImageNtHeaders64;
    FRebased: Boolean;
    FRedirected: Boolean;
    FSections: array of TImageSectionHeader;
    FSizeOfFileImage: Int64;
    FVirtualSizeOfImage: Int64;
    function AlignDown(Value: DWORD; Align: DWORD): DWORD;
    function AlignUp(Value: DWORD; Align: DWORD): DWORD;
    function DirectoryIndexFromRva(RvaAddr: DWORD): Integer;
    function GetSectionData(RvaAddr: DWORD; var Data: TSectionData): Boolean;
    procedure InitDirectories;
    function IsExportForvarded(RvaAddr: DWORD): Boolean;
    procedure LoadFromImage;
    function LoadNtHeader(Raw: TStream): Boolean;
    function LoadSections(Raw: TStream): Boolean;
    function LoadExport(Raw: TStream): Boolean;
    procedure ProcessApiSetRedirect(const LibName: string;
      var ExportChunk: TExportChunk);
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
    property ComPlusILOnly: Boolean read FILOnly;
    property EntryPoint: ULONG_PTR64 read FEntryPoint;
    property EntryPointList: TList<TEntryPointChunk> read FEntryPoints;
    property ExportList: TList<TExportChunk> read FExport;
    property ExportDirectory: TDirectoryData read FExportDir;
    property Image64: Boolean read FImage64;
    property ImageBase: ULONG_PTR64 read FImageBase;
    property ImageName: string read FImageName;
    property ImagePath: string read FImagePath;
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
  FExport := TList<TExportChunk>.Create;
  FExportIndex := TDictionary<string, Integer>.Create;
  FExportOrdinalIndex := TDictionary<Word, Integer>.Create;
  FEntryPoints := TList<TEntryPointChunk>.Create;
  LoadFromImage;
end;

destructor TRawPEImage.Destroy;
begin
  FEntryPoints.Free;
  FExportIndex.Free;
  FExportOrdinalIndex.Free;
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
  with FNtHeader.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT] do
  begin
    FExportDir.VirtualAddress := RvaToVa(VirtualAddress);
    FExportDir.Size := Size;
  end;
end;

function TRawPEImage.IsExportForvarded(RvaAddr: DWORD): Boolean;
begin
  // перенаправленые функции в качестве адреса содержат указатель на
  // строку перенаправления обычно размещенную в директории экспорта
  Result := DirectoryIndexFromRva(RvaAddr) = IMAGE_DIRECTORY_ENTRY_EXPORT;
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

    // загрузка NT заголовка, всегда ввиде 64 битной структуры
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

    // инициализируем адрес и параметры таблицы экспорта
    InitDirectories;

    // читаем директорию экспорта
    LoadExport(Raw);

  finally
    Raw.Free;
  end;
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
  var ExportChunk: TExportChunk);
begin
  // это пока заглушка, её будем расширять далее
  ExportChunk.ForvardedTo := ExportChunk.OriginalForvardedTo;
  ExportChunk.OriginalForvardedTo := EmptyStr;
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
