program test;

{$APPTYPE CONSOLE}

{$R *.res}

uses
  Windows,
  System.SysUtils,
  RawScanner.ModulesData in 'RawScanner.ModulesData.pas',
  RawScanner.Types in 'RawScanner.Types.pas',
  RawScanner.Utils in 'RawScanner.Utils.pas';

var
  Raw: TRawPEImage;
  hLib: THandle;
  ExportFunc: TExportChunk;
begin
  hLib := GetModuleHandle('ntdll.dll');
  Raw := TRawPEImage.Create('c:\windows\system32\ntdll.dll', ULONG64(hLib));
  try
    Writeln('Export count: ', Raw.ExportList.Count);
    for ExportFunc in Raw.ExportList do
      if ExportFunc.FuncAddrVA <> ULONG64(GetProcAddress(hLib, PChar(ExportFunc.FuncName))) then
        Writeln(ExportFunc.FuncName, ' wrong addr: ', ExportFunc.FuncAddrVA);
  finally
    Raw.Free;
  end;
end.
