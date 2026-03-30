using System.Collections.Generic;
using AsmResolver.DotNet;
using AsmResolver.PE.DotNet.Cil;
using Krypton.Core.Architecture;

namespace Krypton.Core.PatternMatching.Patterns
{
    public class Ldarg : IPattern
    {
        public VMOpCode Translates => VMOpCode.Ldarg;

        public IList<CilOpCode> Pattern => new List<CilOpCode>
        {
            CilOpCodes.Ldarg_0,
            CilOpCodes.Ldfld,
            CilOpCodes.Ldarg_0,
            CilOpCodes.Ldfld,
            CilOpCodes.Ldarg_0,
            CilOpCodes.Ldfld,
            CilOpCodes.Unbox_Any,
            CilOpCodes.Ldelem_Ref,
            CilOpCodes.Callvirt,
            CilOpCodes.Ret
        };

        public bool Verify(MethodDefinition Method, int index)
        {
            return true;
        }
    }

    public class Conv_I4 : IPattern
    {
        public VMOpCode Translates => VMOpCode.Conv_I4;

        public IList<CilOpCode> Pattern => new List<CilOpCode>
        {
            CilOpCodes.Ldarg_0,
            CilOpCodes.Ldfld,
            CilOpCodes.Callvirt,
            CilOpCodes.Call,
            CilOpCodes.Stloc_S,
            CilOpCodes.Ldloc_S,
            CilOpCodes.Brfalse,
            CilOpCodes.Ldarg_0,
            CilOpCodes.Ldfld,
            CilOpCodes.Ldloc_S,
            CilOpCodes.Callvirt,
            CilOpCodes.Callvirt,
            CilOpCodes.Ret
        };

        public bool Verify(MethodDefinition Method, int index)
        {
            var instructions = Method.CilMethodBody.Instructions;
            return index + 10 < instructions.Count &&
                   PatternHelpers.CalleeContainsOpCode(Method, instructions[index + 10], CilCode.Conv_I4, 5);
        }
    }

    public class Conv_I8 : IPattern
    {
        public VMOpCode Translates => VMOpCode.Conv_I8;

        public IList<CilOpCode> Pattern => new List<CilOpCode>
        {
            CilOpCodes.Ldarg_0,
            CilOpCodes.Ldfld,
            CilOpCodes.Callvirt,
            CilOpCodes.Call,
            CilOpCodes.Stloc_S,
            CilOpCodes.Ldloc_S,
            CilOpCodes.Brfalse,
            CilOpCodes.Ldarg_0,
            CilOpCodes.Ldfld,
            CilOpCodes.Ldloc_S,
            CilOpCodes.Callvirt,
            CilOpCodes.Callvirt,
            CilOpCodes.Ret
        };

        public bool Verify(MethodDefinition Method, int index)
        {
            var instructions = Method.CilMethodBody.Instructions;
            return index + 10 < instructions.Count &&
                   PatternHelpers.CalleeContainsOpCode(Method, instructions[index + 10], CilCode.Conv_I8, 5);
        }
    }

    public class Conv_U1 : IPattern
    {
        public VMOpCode Translates => VMOpCode.Conv_U1;

        public IList<CilOpCode> Pattern => new List<CilOpCode>
        {
            CilOpCodes.Ldarg_0,
            CilOpCodes.Ldfld,
            CilOpCodes.Callvirt,
            CilOpCodes.Call,
            CilOpCodes.Stloc_S,
            CilOpCodes.Ldloc_S,
            CilOpCodes.Brfalse,
            CilOpCodes.Ldarg_0,
            CilOpCodes.Ldfld,
            CilOpCodes.Ldloc_S,
            CilOpCodes.Callvirt,
            CilOpCodes.Callvirt,
            CilOpCodes.Ret
        };

        public bool Verify(MethodDefinition Method, int index)
        {
            var instructions = Method.CilMethodBody.Instructions;
            return index + 10 < instructions.Count &&
                   PatternHelpers.CalleeContainsOpCode(Method, instructions[index + 10], CilCode.Conv_U1, 5);
        }
    }

    public class Not : IPattern
    {
        public VMOpCode Translates => VMOpCode.Not;

        public IList<CilOpCode> Pattern => new List<CilOpCode>
        {
            CilOpCodes.Ldarg_0,
            CilOpCodes.Ldfld,
            CilOpCodes.Callvirt,
            CilOpCodes.Call,
            CilOpCodes.Stloc_S,
            CilOpCodes.Ldloc_S,
            CilOpCodes.Brfalse,
            CilOpCodes.Ldarg_0,
            CilOpCodes.Ldfld,
            CilOpCodes.Ldloc_S,
            CilOpCodes.Callvirt,
            CilOpCodes.Callvirt,
            CilOpCodes.Ret
        };

        public bool Verify(MethodDefinition Method, int index)
        {
            var instructions = Method.CilMethodBody.Instructions;
            return index + 10 < instructions.Count &&
                   PatternHelpers.CalleeContainsOpCode(Method, instructions[index + 10], CilCode.Not, 5);
        }
    }

    public class Add : IPattern
    {
        public VMOpCode Translates => VMOpCode.Add;

        public IList<CilOpCode> Pattern => new List<CilOpCode>
        {
            CilOpCodes.Ldarg_0,
            CilOpCodes.Ldfld,
            CilOpCodes.Callvirt,
            CilOpCodes.Call,
            CilOpCodes.Stloc_S,
            CilOpCodes.Ldarg_0,
            CilOpCodes.Ldfld,
            CilOpCodes.Callvirt,
            CilOpCodes.Call,
            CilOpCodes.Stloc_S,
            CilOpCodes.Ldloc_S,
            CilOpCodes.Brfalse,
            CilOpCodes.Ldloc_S,
            CilOpCodes.Brfalse,
            CilOpCodes.Ldarg_0,
            CilOpCodes.Ldfld,
            CilOpCodes.Ldloc_S,
            CilOpCodes.Ldloc_S,
            CilOpCodes.Callvirt,
            CilOpCodes.Callvirt,
            CilOpCodes.Ret
        };

        public bool Verify(MethodDefinition Method, int index)
        {
            var instructions = Method.CilMethodBody.Instructions;
            return index + 18 < instructions.Count &&
                   PatternHelpers.CalleeContainsOpCode(Method, instructions[index + 18], CilCode.Add, 5);
        }
    }

    public class Xor : IPattern
    {
        public VMOpCode Translates => VMOpCode.Xor;

        public IList<CilOpCode> Pattern => new List<CilOpCode>
        {
            CilOpCodes.Ldarg_0,
            CilOpCodes.Ldfld,
            CilOpCodes.Callvirt,
            CilOpCodes.Call,
            CilOpCodes.Stloc_S,
            CilOpCodes.Ldarg_0,
            CilOpCodes.Ldfld,
            CilOpCodes.Callvirt,
            CilOpCodes.Call,
            CilOpCodes.Stloc_S,
            CilOpCodes.Ldloc_S,
            CilOpCodes.Brfalse,
            CilOpCodes.Ldloc_S,
            CilOpCodes.Brfalse,
            CilOpCodes.Ldarg_0,
            CilOpCodes.Ldfld,
            CilOpCodes.Ldloc_S,
            CilOpCodes.Ldloc_S,
            CilOpCodes.Callvirt,
            CilOpCodes.Callvirt,
            CilOpCodes.Ret
        };

        public bool Verify(MethodDefinition Method, int index)
        {
            var instructions = Method.CilMethodBody.Instructions;
            return index + 18 < instructions.Count &&
                   PatternHelpers.CalleeContainsOpCode(Method, instructions[index + 18], CilCode.Xor, 5);
        }
    }

    public class Shl : IPattern
    {
        public VMOpCode Translates => VMOpCode.Shl;

        public IList<CilOpCode> Pattern => new List<CilOpCode>
        {
            CilOpCodes.Ldarg_0,
            CilOpCodes.Ldfld,
            CilOpCodes.Callvirt,
            CilOpCodes.Call,
            CilOpCodes.Stloc_S,
            CilOpCodes.Ldarg_0,
            CilOpCodes.Ldfld,
            CilOpCodes.Callvirt,
            CilOpCodes.Call,
            CilOpCodes.Stloc_S,
            CilOpCodes.Ldloc_S,
            CilOpCodes.Brfalse,
            CilOpCodes.Ldloc_S,
            CilOpCodes.Brfalse,
            CilOpCodes.Ldarg_0,
            CilOpCodes.Ldfld,
            CilOpCodes.Ldloc_S,
            CilOpCodes.Ldloc_S,
            CilOpCodes.Callvirt,
            CilOpCodes.Callvirt,
            CilOpCodes.Ret
        };

        public bool Verify(MethodDefinition Method, int index)
        {
            var instructions = Method.CilMethodBody.Instructions;
            return index + 18 < instructions.Count &&
                   PatternHelpers.CalleeContainsOpCode(Method, instructions[index + 18], CilCode.Shl, 5);
        }
    }

    public class Shr : IPattern
    {
        public VMOpCode Translates => VMOpCode.Shr;

        public IList<CilOpCode> Pattern => new List<CilOpCode>
        {
            CilOpCodes.Ldarg_0,
            CilOpCodes.Ldfld,
            CilOpCodes.Callvirt,
            CilOpCodes.Call,
            CilOpCodes.Stloc_S,
            CilOpCodes.Ldarg_0,
            CilOpCodes.Ldfld,
            CilOpCodes.Callvirt,
            CilOpCodes.Call,
            CilOpCodes.Stloc_S,
            CilOpCodes.Ldloc_S,
            CilOpCodes.Brfalse,
            CilOpCodes.Ldloc_S,
            CilOpCodes.Brfalse,
            CilOpCodes.Ldarg_0,
            CilOpCodes.Ldfld,
            CilOpCodes.Ldloc_S,
            CilOpCodes.Ldloc_S,
            CilOpCodes.Callvirt,
            CilOpCodes.Callvirt,
            CilOpCodes.Ret
        };

        public bool Verify(MethodDefinition Method, int index)
        {
            var instructions = Method.CilMethodBody.Instructions;
            return index + 18 < instructions.Count &&
                   PatternHelpers.CalleeContainsOpCode(Method, instructions[index + 18], CilCode.Shr, 5);
        }
    }

    public class Sub : IPattern
    {
        public VMOpCode Translates => VMOpCode.Sub;

        public IList<CilOpCode> Pattern => new List<CilOpCode>
        {
            CilOpCodes.Ldarg_0,
            CilOpCodes.Ldfld,
            CilOpCodes.Callvirt,
            CilOpCodes.Call,
            CilOpCodes.Stloc_S,
            CilOpCodes.Ldarg_0,
            CilOpCodes.Ldfld,
            CilOpCodes.Callvirt,
            CilOpCodes.Call,
            CilOpCodes.Stloc_S,
            CilOpCodes.Ldloc_S,
            CilOpCodes.Brfalse,
            CilOpCodes.Ldloc_S,
            CilOpCodes.Brfalse,
            CilOpCodes.Ldarg_0,
            CilOpCodes.Ldfld,
            CilOpCodes.Ldloc_S,
            CilOpCodes.Ldloc_S,
            CilOpCodes.Callvirt,
            CilOpCodes.Callvirt,
            CilOpCodes.Ret
        };

        public bool Verify(MethodDefinition Method, int index)
        {
            var instructions = Method.CilMethodBody.Instructions;
            return index + 18 < instructions.Count &&
                   PatternHelpers.CalleeContainsOpCode(Method, instructions[index + 18], CilCode.Sub, 5);
        }
    }

    public class Ldlen : IPattern
    {
        public VMOpCode Translates => VMOpCode.Ldlen;

        public IList<CilOpCode> Pattern => new List<CilOpCode>
        {
            CilOpCodes.Ldarg_0,
            CilOpCodes.Ldfld,
            CilOpCodes.Callvirt,
            CilOpCodes.Stloc_S,
            CilOpCodes.Ldloc_S,
            CilOpCodes.Ldnull,
            CilOpCodes.Callvirt,
            CilOpCodes.Castclass,
            CilOpCodes.Stloc_S,
            CilOpCodes.Ldarg_0,
            CilOpCodes.Ldfld,
            CilOpCodes.Ldloc_S,
            CilOpCodes.Callvirt,
            CilOpCodes.Ldc_I4_5,
            CilOpCodes.Newobj,
            CilOpCodes.Callvirt,
            CilOpCodes.Ret
        };

        public bool Verify(MethodDefinition Method, int index)
        {
            var instructions = Method.CilMethodBody.Instructions;
            if (index + 12 >= instructions.Count)
                return false;
            return PatternHelpers.CalleeLooksLikeIntLengthGetter(instructions[index + 12]);
        }
    }
}
