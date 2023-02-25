////////////////////////////////////////////////////////////////////////////////
//
//  ****************************************************************************
//  * Unit Name : Debug.TinyLenDisAsm
//  * Purpose   : Простой дизассемблер длин
//  * Author    : Александр (Rouse_) Багель
//  * Version   : 1.0
//  * Fork from : https://github.com/Nomade040/length-disassembler
//  ****************************************************************************
//
//  Иногда промахивается, например для такой инструкции длину отдает в 12 байт:
//  48C7452800000000 mov qword ptr [rbp+$28],$0000000000000000

unit Debug.TinyLenDisAsm;

interface

  function ldisasm(Address: Pointer; x86_64_mode: Boolean): Integer;

implementation

uses
  Math;

type
  size_t = NativeInt;
  uint8_t  = Byte;
  PByteArray = array of Byte;

const
  prefixes: array [0..10] of uint8_t = (
    $F0, $F2, $F3, $2E, $36, $3E, $26, $64, $65, $66, $67);
  op1modrm: array [0..17] of uint8_t = (
    $62, $63, $69, $6B, $C0, $C1, $C4, $C5, $C6, $C7, $D0, $D1, $D2, $D3, $F6, $F7, $FE, $FF);
  op1imm8: array [0..12] of uint8_t = (
    $6A, $6B, $80, $82, $83, $A8, $C0, $C1, $C6, $CD, $D4, $D5, $EB);
  op1imm32: array [0..6] of uint8_t = (
    $68, $69, $81, $A9, $C7, $E8, $E9);
  op2modrm: array [0..8] of uint8_t = (
    $0D, $A3, $A4, $A5, $AB, $AC, $AD, $AE, $AF);

function findByte(arr: PByte; N: size_t; x: uint8_t): Boolean;
begin
  Result := False;
  for var i := 0 to N - 1 do
    if arr[i] = x then
      Exit(True);
end;

procedure parseModRM(var b: PByte; addressPrefix: Boolean);
var
  modrm: uint8_t;
begin
  Inc(b);
  modrm := b^;

  if not addressPrefix or (addressPrefix and (b^ >= $40)) then
  begin
    var hasSIB := False; //Check for SIB byte
    if (b^ < $C0) and (b^ and 7 = 4) and not addressPrefix then
    begin
      hasSIB := True;
      Inc(b);
    end;

    if modrm in [$40..$7F] then // disp8 (ModR/M)
      Inc(b)
    else if (((modrm <= $3F) and (modrm and 7 = 5)) or
      ((modrm >= $80) and (modrm <= $BF))) then //disp16,32 (ModR/M)
      Inc(b, IfThen(addressPrefix, 2, 4))
    else if hasSIB and (b^ and 7 = 5) then //disp8,32 (SIB)
      Inc(b, IfThen(modrm and $40 <> 0, 1, 4));
  end
  else
    if addressPrefix and (modrm = $26) then
      Inc(b, 2);
end;

function ldisasm(Address: Pointer; x86_64_mode: Boolean): Integer;
var
  b: PByte;

  function ifthenb(a, b, c: Boolean): Boolean;
  begin
    if a then
      Result := b
    else
      Result := c;
  end;

  function R: Byte;
  begin
    Result := b^ shr 4;
  end;

  function C: Byte;
  begin
    Result := b^ and $F;
  end;

begin
  var offset: size_t := 0;
  var operandPrefix: Boolean := False;
  var addressPrefix: Boolean := False;
  var rexW: Boolean := False;
  b := Address;

  //Parse legacy prefixes & REX prefixes
  var i := 0;
  while (i < 14) and
    findByte(@prefixes[0], SizeOf(prefixes), b^) or
      ifthenb(x86_64_mode, R = 4, False) do
  begin
    if b^ = $66 then
      operandPrefix := True
    else if b^ = $67 then
      addressPrefix := True
    else if (R = 4) and (C >= 8) then
      rexW := True;
    Inc(i);
    Inc(b);
  end;

  //Parse opcode(s)
  if b^ = $F then // 2,3 bytes
  begin
    Inc(b);
    if (b^ = $38) or (b^ = $3A) then // 3 bytes
    begin
      if b^ = $3A then
        Inc(offset);
      Inc(b);
      parseModRM(b, addressPrefix);
    end
    else  // 2 bytes
    begin
      if R = 8 then //disp32
        Inc(offset, 4)
      else if ((R = 7) and (C < 4)) or
        (b^ in [$A4, $C2, $C4..$C6, $BA, $AC]) then //imm8
        Inc(offset);

      //Check for ModR/M, SIB and displacement
			if findByte(@op2modrm[0], sizeof(op2modrm), b^) or
        (R in [1, 2, 4..6, 9, $B]) or
        (b^ >= $D0) or
        ((R = 7) and (C <> 7)) or
        ((R = $C) and (C < 8)) or
        ((R = 0) and (C < 4)) then
				parseModRM(b, addressPrefix);

    end;
  end
  else // 1 byte
  begin
    //Check for immediate field
		if //imm8
      ((R = $E) and (C < 8)) or
      ((R = $B) and (C < 8)) or
      (R = 7) or
      ((R < 4) and ((C = 4) or (C = $C))) or
      ((b^ = $F6) and (((b + 1)^ and 48) = 0)) or
      findByte(@op1imm8[0], sizeof(op1imm8), b^) then
  		Inc(offset)
    // imm16
    else if (b^ = $C2) or (b^ = $CA) then
      Inc(offset, 2)
    //imm16 + imm8
    else if (b^ = $C8) then
      Inc(offset, 3)
    //imm32,16
    else if (((R < 4) and ((C = 5) or (C = $D))) or
      ((R = $B) and (C >= 8)) or
      ((b^ = $F7) and (((b + 1)^ and 48) = 0)) or
      findByte(@op1imm32[0], sizeof(op1imm32), b^)) then
      Inc(offset, IfThen(rexW, 8, ifthen(operandPrefix, 2, 4)))
    else if (R = $A) and (C < 4) then
      Inc(offset, IfThen(rexW, 8, ifthen(addressPrefix, 2, 4)))
    else
      //imm32,48
      if (b^ = $EA) or (b^ = $9A) then
        Inc(offset, IfThen(operandPrefix, 4, 6));

    //Check for ModR/M, SIB and displacement
    if findByte(@op1modrm[0], sizeof(op1modrm), b^) or
      ((R < 4) and ((C < 4) or ((C >= 8) and (C < $C)))) or
      (R = 8) or
      ((R = $D) and (C >= 8)) then
      parseModRM(b, addressPrefix);
  end;

  Result := Integer(b + 1 + offset) - Integer(Address);
end;

end.
