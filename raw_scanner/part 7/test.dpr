program test;

{$APPTYPE CONSOLE}

{$R *.res}

uses
  Windows,
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
  RawScanner.ApiSet in 'RawScanner.ApiSet.pas';

var
  AProcessID: DWORD;
  I: Integer;
begin
  Writeln(Win32MajorVersion, '.', Win32MinorVersion, '.', Win32BuildNumber, '.',
    Win32Platform, ' ', Win32CSDVersion);

  // заменить PID на любой другой сторонний процесс!!!
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
    RawScannerCore.Analizer.Analyze(
      // обработка вывода перехваченых таблиц экспорта/импорта
      ProcessTableHook,
      // обработка вывода перехватчиков установленых непосредственно в коде функций (будет рассмотрен позже)
      nil
      );

  except
    on E: Exception do
      Writeln(E.ClassName, ': ', E.Message);
  end;

  Writeln;
  Writeln('DONE!');

end.

