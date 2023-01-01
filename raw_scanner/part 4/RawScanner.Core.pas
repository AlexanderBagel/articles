unit RawScanner.Core;

interface

uses
  Windows,
  SysUtils,
  Generics.Collections,
  RawScanner.Types,
  RawScanner.LoaderData,
  RawScanner.Wow64;

type
  TPEB64 = record
    InheritedAddressSpace: BOOLEAN;
    ReadImageFileExecOptions: BOOLEAN;
    BeingDebugged: BOOLEAN;
    BitField: BOOLEAN;
    Mutant: ULONG_PTR64;
    ImageBaseAddress: ULONG_PTR64;
    LoaderData: ULONG_PTR64;
    // ...
  end;

  TInitializationResult = record
    Loader32, Loader64: Integer;
  end;

  TRawScanner = class
  strict private
    class var FInstance: TRawScanner;
    class destructor ClassDestroy;
  strict private
    FProcess: THandle;
    FIsWow64Mode: LongBool;
    FInitResult: TInitializationResult;
    FPEB32, FPEB64: TPEB64;
    procedure Clear;
    function GetPEB(AProcess: THandle;
      Read32Peb: Boolean; out APeb: TPEB64): Boolean;
  public
    destructor Destroy; override;
    class function GetInstance: TRawScanner;
    procedure InitFromProcess(AProcessID: Cardinal);
    property InitializationResult: TInitializationResult read FInitResult;
  end;

  function RawScannerCore: TRawScanner;

implementation

function RawScannerCore: TRawScanner;
begin
  Result := TRawScanner.GetInstance;
end;

{ TRawScanner }

class destructor TRawScanner.ClassDestroy;
begin
  FInstance.Free;
end;

procedure TRawScanner.Clear;
begin
  if FProcess <> 0 then
    CloseHandle(FProcess);
  FProcess := 0;
  ZeroMemory(@FPEB32, SizeOf(TPEB64));
  ZeroMemory(@FPEB64, SizeOf(TPEB64));
  ZeroMemory(@FInitResult, SizeOf(TInitializationResult));
end;

destructor TRawScanner.Destroy;
begin
  Clear;
  FInstance := nil;
  inherited;
end;

class function TRawScanner.GetInstance: TRawScanner;
begin
  if FInstance = nil then
    FInstance := TRawScanner.Create;
  Result := FInstance;
end;

function TRawScanner.GetPEB(AProcess: THandle; Read32Peb: Boolean;
  out APeb: TPEB64): Boolean;
begin

end;

procedure TRawScanner.InitFromProcess(AProcessID: Cardinal);
var
  Loader: TLoaderData;
begin
  Clear;
  FProcess := OpenProcess(
    PROCESS_QUERY_INFORMATION or PROCESS_VM_READ,
    False, AProcessID);

  if FProcess = 0 then
    Exit;

  Wow64Support.IsWow64Process(FProcess, FIsWow64Mode);

  {$IFDEF WIN32}
  // если мы в 32 битном коде и в 32 битной системе
  if not Wow64Support.Use64AddrMode then
    // то нам доступен только 32 битный PEB
    GetPEB(FProcess, True, FPEB32)
  else
  {$ENDIF}
  begin
    // в противном случае мы в 64 битной OS,
    // где у любого процесса есть 64 битный PEB
    GetPEB(FProcess, False, FPEB64);
    // а 32 битный есть только у 32 битных процессов
    if FIsWow64Mode then
      GetPEB(FProcess, True, FPEB32);
  end;

  // загружаем информацию от лоадера
  Loader := TLoaderData.Create(FProcess, FIsWow64Mode);
  try
    FInitResult.Loader32 := Loader.Load32LoaderData(FPEB32.LoaderData);
    FInitResult.Loader64 := Loader.Load64LoaderData(FPEB64.LoaderData);
  finally
    Loader.Free;
  end;
end;

end.
