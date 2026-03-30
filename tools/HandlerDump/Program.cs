using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using AsmResolver.DotNet;
using AsmResolver.PE.DotNet.Cil;

if (args.Length < 2)
{
    Console.WriteLine("usage: HandlerDump <assembly> <vm-byte-hex> [vm-byte-hex ...]");
    return;
}

var module = ModuleDefinition.FromFile(args[0]);
var opcodeHandlerMethod = module.GetAllTypes()
    .SelectMany(t => t.Methods)
    .FirstOrDefault(m => m.IsIL && m.CilMethodBody != null &&
                         m.CilMethodBody.Instructions.Count >= 3200 &&
                         m.CilMethodBody.Instructions.Count(i => i.OpCode == CilOpCodes.Switch) == 1);

if (opcodeHandlerMethod?.CilMethodBody == null)
{
    Console.WriteLine("handler method not found");
    return;
}

var body = opcodeHandlerMethod.CilMethodBody;
var switchInstruction = body.Instructions.First(i => i.OpCode == CilOpCodes.Switch);
var labels = (IList<ICilLabel>) switchInstruction.Operand;

var requested = new List<int>();
for (var i = 1; i < args.Length; i++)
{
    var raw = args[i].Replace("0x", "", StringComparison.OrdinalIgnoreCase);
    requested.Add(int.Parse(raw, NumberStyles.HexNumber, CultureInfo.InvariantCulture));
}

foreach (var vm in requested.Distinct())
{
    if (vm < 0 || vm >= labels.Count || labels[vm] is not CilInstructionLabel label)
    {
        Console.WriteLine($"vm 0x{vm:X2}: out of range");
        continue;
    }

    var start = body.Instructions.IndexOf(label.Instruction);
    Console.WriteLine($"==== vm 0x{vm:X2} start={start} ====");

    for (var i = start; i < body.Instructions.Count; i++)
    {
        var instruction = body.Instructions[i];
        var operand = instruction.Operand == null ? string.Empty : " " + instruction.Operand;
        Console.WriteLine($"[{i}] {instruction.OpCode.Code}{operand}");
        if (instruction.OpCode == CilOpCodes.Ret)
            break;
    }

    Console.WriteLine();
}
