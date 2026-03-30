using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using AsmResolver.DotNet;
using AsmResolver.PE.DotNet.Cil;
using Krypton.Core;
using Krypton.Core.PatternMatching;

if (args.Length < 2)
{
    Console.WriteLine("usage: PatternProbe <assembly> <vm-byte-hex> [vm-byte-hex ...]");
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

var instructions = opcodeHandlerMethod.CilMethodBody.Instructions.ToList();
var switchInstruction = opcodeHandlerMethod.CilMethodBody.Instructions.First(i => i.OpCode == CilOpCodes.Switch);
var labels = (IList<ICilLabel>) switchInstruction.Operand;

var patterns = typeof(PatternMatcher).Assembly.GetTypes()
    .Where(t => typeof(IPattern).IsAssignableFrom(t) && !t.IsInterface && !t.IsAbstract)
    .Select(t => (IPattern) Activator.CreateInstance(t)!)
    .OrderByDescending(p => p.Pattern.Count)
    .ToList();

foreach (var rawArg in args.Skip(1))
{
    var raw = rawArg.Replace("0x", "", StringComparison.OrdinalIgnoreCase);
    var vm = int.Parse(raw, NumberStyles.HexNumber, CultureInfo.InvariantCulture);
    if (vm < 0 || vm >= labels.Count || labels[vm] is not CilInstructionLabel label)
    {
        Console.WriteLine($"vm 0x{vm:X2}: out of range");
        continue;
    }

    var index = instructions.IndexOf(label.Instruction!);
    Console.WriteLine($"==== vm 0x{vm:X2} @ {index} ====");
    var any = false;
    foreach (var pat in patterns)
    {
        if (!Matches(pat.Pattern, instructions, index))
            continue;
        any = true;
        var ok = pat.Verify(opcodeHandlerMethod, index);
        Console.WriteLine($"{pat.GetType().Name} => {pat.Translates} | verify={ok}");
    }
    if (!any)
        Console.WriteLine("<no pattern match>");

    Console.WriteLine();
}

static bool Matches(IList<CilOpCode> pattern, List<CilInstruction> instructions, int index)
{
    if (index + pattern.Count > instructions.Count)
        return false;

    for (var i = 0; i < pattern.Count; i++)
    {
        if (pattern[i] == CilOpCodes.Nop)
            continue;
        if (instructions[index + i].OpCode != pattern[i])
            return false;
    }

    return true;
}
