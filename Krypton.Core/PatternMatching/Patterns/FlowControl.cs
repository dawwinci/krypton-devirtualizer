using System.Collections.Generic;
using AsmResolver.DotNet;
using AsmResolver.PE.DotNet.Cil;
using Krypton.Core.Architecture;

namespace Krypton.Core.PatternMatching.Patterns
{
    public class BrWithLeaveFlag : IPattern
    {
        public VMOpCode Translates => VMOpCode.Br;

        public IList<CilOpCode> Pattern => new List<CilOpCode>
        {
            CilOpCodes.Ldarg_0,
            CilOpCodes.Ldarg_0,
            CilOpCodes.Ldfld,
            CilOpCodes.Unbox_Any,
            CilOpCodes.Ldc_I4_1,
            CilOpCodes.Sub,
            CilOpCodes.Stfld,
            CilOpCodes.Ldarg_0,
            CilOpCodes.Ldc_I4_1,
            CilOpCodes.Stfld,
            CilOpCodes.Ret
        };

        public bool Verify(MethodDefinition Method, int index)
        {
            return true;
        }
    }

    public class Leave : IPattern
    {
        public VMOpCode Translates => VMOpCode.Leave;

        public IList<CilOpCode> Pattern => new List<CilOpCode>
        {
            CilOpCodes.Ldarg_0,
            CilOpCodes.Ldc_I4_1,
            CilOpCodes.Stfld,
            CilOpCodes.Ret
        };

        public bool Verify(MethodDefinition Method, int index)
        {
            return true;
        }
    }

    public class Ret : IPattern
    {
        public VMOpCode Translates => VMOpCode.Ret;

        public IList<CilOpCode> Pattern => new List<CilOpCode>
        {
            CilOpCodes.Ldarg_0,
            CilOpCodes.Ldc_I4_S,
            CilOpCodes.Stfld
        };

        public bool Verify(MethodDefinition Method, int index)
        {
            var instructions = Method.CilMethodBody.Instructions;
            if (index + 1 >= instructions.Count)
                return false;

            // The return handler marks VM state with -3 before unwinding.
            return PatternHelpers.IsIntConstant(instructions[index + 1], -3);
        }
    }
}
