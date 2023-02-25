program test;

{$APPTYPE CONSOLE}

{$R *.res}

uses
  Windows,
  TlHelp32,
  System.SysUtils,
  RawScanner.ModulesData in 'RawScanner.ModulesData.pas',
  RawScanner.Types in 'RawScanner.Types.pas',
  RawScanner.Utils in 'RawScanner.Utils.pas',
  RawScanner.LoaderData in 'RawScanner.LoaderData.pas',
  RawScanner.Wow64 in 'RawScanner.Wow64.pas',
  RawScanner.Core in 'RawScanner.Core.pas',
  RawScanner.Analyzer in 'RawScanner.Analyzer.pas',
  display_utils in 'display_utils.pas',
  RawScanner.X64Gates in 'RawScanner.X64Gates.pas',
  RawScanner.ApiSet in 'RawScanner.ApiSet.pas',
  Debug.TinyLenDisAsm in 'Debug.TinyLenDisAsm.pas';

function GetParentPID: Integer;
var
  hProcessSnap: THandle;
  processEntry: TProcessEntry32;
  ProcessID: DWORD;
begin
  Result := 0;
  ProcessID := GetCurrentProcessId;
  hProcessSnap := CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
  try
    FillChar(processEntry, SizeOf(TProcessEntry32), #0);
    processEntry.dwSize := SizeOf(TProcessEntry32);
    if not Process32First(hProcessSnap, processEntry) then Exit;
    repeat
      // Сравнение
      if processEntry.th32ProcessID = ProcessID then
      begin
        // Если нашли нужный процесс - выводим результат и выходим
        Result := processEntry.th32ParentProcessID;
        Break;
      end;
    // ищем пока не кончатся процессы
    until not Process32Next(hProcessSnap, processEntry);
  finally
    CloseHandle(hProcessSnap);
  end;
  hProcessSnap := OpenProcess(
    PROCESS_QUERY_INFORMATION or PROCESS_VM_READ,
    False, Result);
  if hProcessSnap = 0 then
    Result := 0
  else
    CloseHandle(hProcessSnap);
end;

var
  AProcessID: DWORD;
  I: Integer;
  AnalizeResult: TAnalizeResult;
begin
  Writeln(Win32MajorVersion, '.', Win32MinorVersion, '.', Win32BuildNumber, '.',
    Win32Platform, ' ', Win32CSDVersion);

  AProcessID := GetParentPID;
  if AProcessID = 0 then
    AProcessID := GetCurrentProcessId;

  // для отключения ошибочного вывода что не найден отложеный импорт
  // imagehlp.dll -> dbghelp.UnDecorateSymbolName который будет подгружен
  // позже на снятии декорации с имен функций,
  // перед проверкой самого себя подгрузим dbghelp.dll чтобы он присутствовал
  // в списках
  if AProcessID = GetCurrentProcessId then
    LoadLibrary('dbghelp.dll');

  RawScannerCore.InitFromProcess(AProcessID);

  Writeln('Loader32: ', RawScannerCore.InitializationResult.Loader32);
  Writeln('Loader64: ', RawScannerCore.InitializationResult.Loader64);
  Writeln('Use64AddrMode: ', Wow64Support.Use64AddrMode);
  if ApiSetRedirector.Version = 0 then
    Writeln('ApiSet disabled')
  else
  begin
    Writeln('ApiSet version: ', ApiSetRedirector.Version);
    Writeln('ApiSet entries cout: ', ApiSetRedirector.Count);
  end;

  for I := 0 to RawScannerCore.Modules.Items.Count - 1 do
    ShowModuleInfo(I, RawScannerCore.Modules.Items[I]);

  if RawScannerCore.Active then
  try
    AnalizeResult := RawScannerCore.Analizer.Analyze(
      // обработка вывода перехваченых таблиц экспорта/импорта
      ProcessTableHook,
      // обработка вывода перехватчиков установленых непосредственно в коде функций
      ProcessCodeHook
      );

  except
    on E: Exception do
      Writeln(E.ClassName, ': ', E.Message);
  end;

  Writeln;
  Writeln('Total modules scanned: ', AnalizeResult.Modules.Scanned);
  Writeln('Total import fields scanned: ', AnalizeResult.Import.Scanned);
  Writeln('Total export fields scanned: ', AnalizeResult.Export.Scanned);
  Writeln('Total code scanned: ', AnalizeResult.Code.Scanned);

  Writeln;
  if ImportCount > 0 then
    Writeln('Import table hook found: ', ImportCount);
  if DImportCount > 0 then
    Writeln('Delayed import table hook found: ', DImportCount);
  if ExportCount > 0 then
    Writeln('Export table hook found: ', ExportCount);
  if CodeCount > 0 then
    Writeln('Code hook found: ', CodeCount);

  Writeln;
  Writeln('DONE!');

end.

