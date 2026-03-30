using System.Collections.Generic;
using AsmResolver.DotNet;
using AsmResolver.PE.DotNet.Cil;
using Krypton.Core.Architecture;

namespace Krypton.Core.PatternMatching.Patterns
{
    public class Newobj : IPattern
    {
        public VMOpCode Translates => VMOpCode.Newobj;

        public IList<CilOpCode> Pattern => new List<CilOpCode>
        {
            CilOpCodes.Ldarg_0,
            CilOpCodes.Ldfld,
            CilOpCodes.Unbox_Any,
            CilOpCodes.Stloc_S,
            CilOpCodes.Ldc_I4,
            CilOpCodes.Call,
            CilOpCodes.Call,
            CilOpCodes.Callvirt,
            CilOpCodes.Stloc_S,
            CilOpCodes.Ldloc_S,
            CilOpCodes.Ldloc_S,
            CilOpCodes.Callvirt,
            CilOpCodes.Castclass,
            CilOpCodes.Stloc_S
        };

        public bool Verify(MethodDefinition Method, int index)
        {
            var instructions = Method.CilMethodBody.Instructions;
            return index + 11 < instructions.Count &&
                   PatternHelpers.CallsMethodNamed(instructions[index + 11], "ResolveMethod");
        }
    }

    public class Newarr : IPattern
    {
        public VMOpCode Translates => VMOpCode.Newarr;

        public IList<CilOpCode> Pattern => new List<CilOpCode>
        {
            CilOpCodes.Ldarg_0,
            CilOpCodes.Ldfld,
            CilOpCodes.Unbox_Any,
            CilOpCodes.Stloc_S,
            CilOpCodes.Ldc_I4,
            CilOpCodes.Call,
            CilOpCodes.Call,
            CilOpCodes.Callvirt,
            CilOpCodes.Stloc_S,
            CilOpCodes.Ldloc_S,
            CilOpCodes.Ldloc_S,
            CilOpCodes.Callvirt,
            CilOpCodes.Stloc_S
        };

        public bool Verify(MethodDefinition Method, int index)
        {
            var instructions = Method.CilMethodBody.Instructions;
            return index + 11 < instructions.Count &&
                   PatternHelpers.CallsMethodNamed(instructions[index + 11], "ResolveType");
        }
    }
}
