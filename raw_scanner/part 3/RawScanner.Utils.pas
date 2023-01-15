unit RawScanner.Utils;

interface

uses
  Windows,
  SysUtils,
  StrUtils,
  ImageHlp,
  PsApi,
  RawScanner.Types,
  RawScanner.Wow64;

  procedure SetNtQueryVirtualMemoryAddr(AddrRva: ULONG_PTR64);
  function ReadRemoteMemory(hProcess: THandle; const lpBaseAddress: ULONG_PTR64;
    lpBuffer: Pointer; nSize: SIZE_T): Boolean;
  function GetMappedFileName64(hProcess: THandle; lpv: ULONG_PTR64;
    lpFilename: LPCWSTR; nSize: DWORD): DWORD;
  function UnDecorateSymbolName(const Value: string): string;

implementation

{$IFDEF WIN32}
const
  MM_HIGHEST_USER_ADDRESS = $7FFEFFFF;

type
  NTSTATUS = LONG;

function NT_SUCCESS(Status: NTSTATUS): Boolean; inline;
begin
  Result := Status >= 0;
end;

function RtlNtStatusToDosError(Status: NTSTATUS): DWORD; stdcall;
  external 'ntdll.dll';

function BaseSetLastNTError(Status: NTSTATUS): ULONG;
begin
  Result := RtlNtStatusToDosError(Status);
  SetLastError(Result);
end;

function NtQueryVirtualMemory64(FuncRVA: ULONG_PTR64; hProcess: THandle;
  BaseAddress: ULONG_PTR64; MemoryInformationClass: DWORD;
  MemoryInformation: Pointer; MemoryInformationLength: DWORD;
  ReturnLength: PULONG64): NTSTATUS; assembler; stdcall;
asm
  // выравниваем стек по 8-байтной границе
  mov eax, esp
  and eax, 7
  cmp eax, 0
  je @stack_aligned

  // если стек не выровнен, в EAX будет оффсет от ESP на сколько
  // сдвинулись данные на 32-битном стеке
  sub esp, eax

@stack_aligned:

  // переключение в 64 битный режим
  push $33                        // пишем новый сегмент кода
  db $E8, 0, 0, 0, 0              // call +5
  add [esp], 5                    // правим адрес возврата на идущий за retf
  retf // дальний возврат со сменой сегмента кода на CS:0х33 + адрес

  // следующий код выполняется в 64 битном режиме
  // в коментариях даны реально выполняющиеся инструкции

  push ebp                              // push rbp
  sub esp, $30                          // sub rsp, $30
  mov ebp, esp                          // mov rbp, rsp

  // параметры пришедшие из 32 бит лежат на стеке
  // нам их нужно только забрать в правильном порядке и по правильным оффсетам
  db $48 lea eax, [esp + eax + $60]     // lea rax, [rsp + rax + $60]

  // на 64 битный стек идут два параметра
  // 1. ReturnLength
  mov ecx, [eax]                        // mov ecx, dword ptr [rax]
  db $48 mov [esp + $28], ecx           // mov [rsp + $28], rcx

  // 2. и размер данных "MemoryInformationLength"
  mov ecx, [eax - 4]                    // mov ecx, dword ptr [rax - 4]
  db $48 mov [esp + $20], ecx           // mov [rsp + $20], rcx

  // регистр R9 содержит указатель на память (MemoryInformation),
  // куда будет помещаться результат
  db $44 mov ecx, [eax - 8]             // mov r9d, dword ptr [rax - 8]

  // регистр R8 содержит идентификатор MemoryInformationClass
  db $44 mov eax, [eax - $C]            // mov r8d, dword ptr [rax - $С]

  // регистр RDX содержит BaseAddress
  db $48 mov edx, [eax - $14]           // mov rdx, [rax - $14]

  // RCX должен содержать hProcess
  mov ecx, [eax - $18]                  // mov ecx, dword ptr [rax - $18]

  // осталось сделать вызов по адресу FuncRVA, идущий из 32 бит через стек
  call [eax - $20]                      // call [rax - $20]

  // подчищаем за собой 64 битный стек
  lea esp, [ebp + $30]                  // lea rsp, [rbp + $30]
  pop ebp                               // pop rbp

  // обратное переключение в 32 битный режим
  // важный момент, в 64 битах RETF всеравно требует два дворда на стеке (8 байт)
  // поэтому выход через два PUSH будет не правильным!!!
  db $E8, 0, 0, 0, 0              // call +5
  mov [esp + 4], $23              // mov dword ptr [rsp + 4], $23
  add [esp], $0D                  // add dword ptr [rsp], $0D
  retf                            // дальний возврат со сменой сегмента кода на CS:0х23 + адрес

  // начиная отсюда мы опять в 32 битном режиме

  // схлопываем фрейм стека нивелируя выравнивание по границе 8 байт
  // сделанное перед переключением в 64 битный режим
  mov esp, ebp
end;
{$ENDIF}

var
  NtQueryVirtualMemoryAddr: ULONG_PTR64 = 0;

procedure SetNtQueryVirtualMemoryAddr(AddrRva: ULONG_PTR64);
begin
  NtQueryVirtualMemoryAddr := AddrRva;
end;

function GetMappedFileName64(hProcess: THandle; lpv: ULONG_PTR64;
  lpFilename: LPCWSTR; nSize: DWORD): DWORD;
{$IFDEF WIN32}
const
  MemoryMappedFilenameInformation = 2;
type
  PMappedFileName = ^TMappedFileName;
  TMappedFileName = record
    ObjectNameInfo: UNICODE_STRING64;
    FileName: array [0..MAX_PATH - 1] of Char;
  end;

var
  MappedFileName: PMappedFileName;
  Status: NTSTATUS;
  cb: DWORD;
  ReturnLength: ULONG64;
{$ENDIF}
begin
{$IFDEF WIN32}
  Result := 0;
  if NtQueryVirtualMemoryAddr <> 0 then
  begin
    // структура TMappedFileName должна быть выровнена по 8-байтной границе
    // поэтому стек не используем, а выделяем принудительно
    MappedFileName := VirtualAlloc(nil,
      SizeOf(TMappedFileName), MEM_COMMIT, PAGE_READWRITE);
    try
      Status := NtQueryVirtualMemory64(NtQueryVirtualMemoryAddr, hProcess, lpv,
        MemoryMappedFilenameInformation, MappedFileName,
        SizeOf(TMappedFileName), @ReturnLength);

      if not NT_SUCCESS(Status) then
      begin
        BaseSetLastNTError(Status);
        Exit(0);
      end;

      nSize := nSize shl 1;
      cb := MappedFileName^.ObjectNameInfo.MaximumLength;

      if nSize < cb then
        cb := nSize;

      Move(MappedFileName^.FileName[0], lpFilename^, cb);

      if cb = MappedFileName^.ObjectNameInfo.MaximumLength then
        Dec(cb, SizeOf(WChar));

      Result := cb shr 1;

    finally
      VirtualFree(MappedFileName, SizeOf(TMappedFileName), MEM_RELEASE);
    end;
  end
  else
  {$ENDIF}
  Result := GetMappedFileName(hProcess, Pointer(lpv), lpFilename, nSize);
end;

function ReadRemoteMemory(hProcess: THandle; const lpBaseAddress: ULONG_PTR64;
  lpBuffer: Pointer; nSize: SIZE_T): Boolean;
var
  {$IFDEF WIN32}
  uReturnLength: ULONG64;
  {$ENDIF}
  ReturnLength: NativeUInt;
begin
  {$IFDEF WIN32}
  if Wow64Support.Use64AddrMode then
    Result := Wow64Support.ReadVirtualMemory(hProcess, lpBaseAddress,
      lpBuffer, nSize, uReturnLength)
  else
    Result := ReadProcessMemory(hProcess, Pointer(lpBaseAddress),
      lpBuffer, nSize, ReturnLength);
  {$ELSE}
  Result := ReadProcessMemory(hProcess, Pointer(lpBaseAddress),
    lpBuffer, nSize, ReturnLength);
  {$ENDIF}
end;

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
