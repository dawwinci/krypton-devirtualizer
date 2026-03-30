using System;
using System.Collections.Generic;
using System.Linq;
using AsmResolver.DotNet;
using AsmResolver.PE.DotNet.Cil;
using Krypton.Core.Architecture;

namespace Krypton.Core.PatternMatching.Patterns
{
    // Stores a computed byte value into an array slot (array, index, value).
    public class ReactorStelemI1ViaArrayAnnotation : IPattern
    {
        public VMOpCode Translates => VMOpCode.Stelem_I1;

        public IList<CilOpCode> Pattern => new List<CilOpCode>
        {
            CilOpCodes.Ldarg_0,
            CilOpCodes.Ldfld,
            CilOpCodes.Callvirt,
            CilOpCodes.Stloc_S,
            CilOpCodes.Ldarg_0,
            CilOpCodes.Ldfld,
            CilOpCodes.Callvirt,
            CilOpCodes.Call,
            CilOpCodes.Stloc_S,
            CilOpCodes.Ldarg_0,
            CilOpCodes.Ldfld,
            CilOpCodes.Callvirt,
            CilOpCodes.Ldnull,
            CilOpCodes.Callvirt,
            CilOpCodes.Castclass,
            CilOpCodes.Dup,
            CilOpCodes.Ldsfld,
            CilOpCodes.Call,
            CilOpCodes.Ldsfld,
            CilOpCodes.Call,
            CilOpCodes.Stloc_S,
            CilOpCodes.Ldloc_S,
            CilOpCodes.Ldloc_S,
            CilOpCodes.Callvirt,
            CilOpCodes.Ldloc_S,
            CilOpCodes.Callvirt,
            CilOpCodes.Ldflda,
            CilOpCodes.Ldfld,
            CilOpCodes.Ldsfld,
            CilOpCodes.Call,
            CilOpCodes.Ret
        };

        public bool Verify(MethodDefinition Method, int index)
        {
            var instructions = Method.CilMethodBody.Instructions.ToList();
            return index + 29 < instructions.Count &&
                   PatternHelpers.CallsMethodNamed(instructions[index + 23], "DefineInterruptibleAuthorizer") &&
                   PatternHelpers.CallsMethodOnType(instructions[index + 29], "UpdateTransaction", "AnnotationOrder");
        }
    }

    // Loads one byte from an array slot and pushes it as a VM value.
    public class ReactorLdelemU1ViaArrayAnnotation : IPattern
    {
        public VMOpCode Translates => VMOpCode.Ldelem_U1;

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
            CilOpCodes.Ldnull,
            CilOpCodes.Callvirt,
            CilOpCodes.Castclass,
            CilOpCodes.Ldloc_S,
            CilOpCodes.Callvirt,
            CilOpCodes.Ldflda,
            CilOpCodes.Ldfld,
            CilOpCodes.Ldsfld,
            CilOpCodes.Call,
            CilOpCodes.Stloc_S,
            CilOpCodes.Ldarg_0,
            CilOpCodes.Ldfld,
            CilOpCodes.Ldtoken,
            CilOpCodes.Ldsfld,
            CilOpCodes.Call,
            CilOpCodes.Ldloc_S,
            CilOpCodes.Call,
            CilOpCodes.Callvirt,
            CilOpCodes.Ret
        };

        public bool Verify(MethodDefinition Method, int index)
        {
            var instructions = Method.CilMethodBody.Instructions.ToList();
            if (index + 25 >= instructions.Count)
                return false;

            if (!(instructions[index + 20].Operand is ITypeDescriptor typeDescriptor) ||
                !string.Equals(typeDescriptor.FullName, "System.Byte", StringComparison.Ordinal))
                return false;

            return PatternHelpers.CallsMethodOnType(instructions[index + 16], "UpdateTransaction", "VirtualAnnotation") &&
                   PatternHelpers.CallsMethodNamed(instructions[index + 24], "DefineExpandableTester") &&
                   PatternHelpers.CallsMethodNamed(instructions[index + 25], "IncludeManager");
        }
    }

    // Pushes null onto the VM stack.
    public class ReactorLdnullViaEvaluatorStruct : IPattern
    {
        public VMOpCode Translates => VMOpCode.Ldnull;

        public IList<CilOpCode> Pattern => new List<CilOpCode>
        {
            CilOpCodes.Ldarg_0,
            CilOpCodes.Ldfld,
            CilOpCodes.Ldnull,
            CilOpCodes.Newobj,
            CilOpCodes.Callvirt,
            CilOpCodes.Ret
        };

        public bool Verify(MethodDefinition Method, int index)
        {
            var instructions = Method.CilMethodBody.Instructions.ToList();
            return index + 4 < instructions.Count &&
                   PatternHelpers.CallsMethodNamed(instructions[index + 4], "IncludeManager");
        }
    }

    // Constructor invocation helper (complex Reactor variant) => Newobj.
    public class ReactorNewobjViaConstructorInvoker : IPattern
    {
        public VMOpCode Translates => VMOpCode.Newobj;

        public IList<CilOpCode> Pattern => new List<CilOpCode>
        {
            CilOpCodes.Ldarg_0,
            CilOpCodes.Ldfld,
            CilOpCodes.Unbox_Any,
            CilOpCodes.Stloc_S,
            CilOpCodes.Ldtoken,
            CilOpCodes.Ldsfld,
            CilOpCodes.Call,
            CilOpCodes.Ldsfld,
            CilOpCodes.Call,
            CilOpCodes.Ldloc_S,
            CilOpCodes.Ldsfld,
            CilOpCodes.Call,
            CilOpCodes.Castclass,
            CilOpCodes.Stloc_S,
            CilOpCodes.Ldloc_S,
            CilOpCodes.Ldsfld,
            CilOpCodes.Call,
            CilOpCodes.Stloc_S,
            CilOpCodes.Ldloc_S,
            CilOpCodes.Ldlen,
            CilOpCodes.Conv_I4,
            CilOpCodes.Newarr,
            CilOpCodes.Stloc_S
        };

        public bool Verify(MethodDefinition Method, int index)
        {
            var instructions = Method.CilMethodBody.Instructions.ToList();
            return PatternHelpers.ContainsMethodCall(instructions, index, 400, "IncludeManager") &&
                   PatternHelpers.ContainsMethodCallOnType(instructions, index, 320, "Invoke", "System.Reflection.ConstructorInfo");
        }
    }

    // Typed array allocation helper => Newarr.
    public class ReactorNewarrViaTypeAndLength : IPattern
    {
        public VMOpCode Translates => VMOpCode.Newarr;

        public IList<CilOpCode> Pattern => new List<CilOpCode>
        {
            CilOpCodes.Ldarg_0,
            CilOpCodes.Ldfld,
            CilOpCodes.Unbox_Any,
            CilOpCodes.Stloc_S,
            CilOpCodes.Ldtoken,
            CilOpCodes.Ldsfld,
            CilOpCodes.Call,
            CilOpCodes.Ldsfld,
            CilOpCodes.Call,
            CilOpCodes.Ldloc_S,
            CilOpCodes.Ldsfld,
            CilOpCodes.Call,
            CilOpCodes.Ldarg_0,
            CilOpCodes.Ldfld,
            CilOpCodes.Callvirt,
            CilOpCodes.Call,
            CilOpCodes.Stloc_S,
            CilOpCodes.Ldloc_S,
            CilOpCodes.Callvirt,
            CilOpCodes.Ldflda,
            CilOpCodes.Ldfld,
            CilOpCodes.Ldsfld,
            CilOpCodes.Call,
            CilOpCodes.Stloc_S,
            CilOpCodes.Ldarg_0,
            CilOpCodes.Ldfld,
            CilOpCodes.Ldloc_S,
            CilOpCodes.Newobj,
            CilOpCodes.Callvirt,
            CilOpCodes.Ret
        };

        public bool Verify(MethodDefinition Method, int index)
        {
            var instructions = Method.CilMethodBody.Instructions.ToList();
            return index + 28 < instructions.Count &&
                   PatternHelpers.CallsMethodOnType(instructions[index + 22], "UpdateTransaction", "TransferableIteratorAnnotation") &&
                   PatternHelpers.CallsMethodNamed(instructions[index + 28], "IncludeManager");
        }
    }

    // Loads a static field value and pushes it onto VM stack.
    public class ReactorLdsfldViaFieldInfoResolver : IPattern
    {
        public VMOpCode Translates => VMOpCode.Ldsfld;

        public IList<CilOpCode> Pattern => new List<CilOpCode>
        {
            CilOpCodes.Ldarg_0,
            CilOpCodes.Ldfld,
            CilOpCodes.Unbox_Any,
            CilOpCodes.Stloc_S,
            CilOpCodes.Ldtoken,
            CilOpCodes.Ldsfld,
            CilOpCodes.Call,
            CilOpCodes.Ldsfld,
            CilOpCodes.Call,
            CilOpCodes.Ldloc_S,
            CilOpCodes.Ldsfld,
            CilOpCodes.Call,
            CilOpCodes.Stloc_S,
            CilOpCodes.Ldarg_0,
            CilOpCodes.Ldfld,
            CilOpCodes.Ldloc_S,
            CilOpCodes.Ldsfld,
            CilOpCodes.Call,
            CilOpCodes.Ldloc_S,
            CilOpCodes.Ldnull,
            CilOpCodes.Ldsfld,
            CilOpCodes.Call,
            CilOpCodes.Call,
            CilOpCodes.Callvirt,
            CilOpCodes.Ret
        };

        public bool Verify(MethodDefinition Method, int index)
        {
            var instructions = Method.CilMethodBody.Instructions.ToList();
            return index + 23 < instructions.Count &&
                   instructions[index + 19].OpCode == CilOpCodes.Ldnull &&
                   PatternHelpers.CallsMethodOnType(instructions[index + 21], "UpdateTransaction", "AnnotationProfiler") &&
                   PatternHelpers.CallsMethodNamed(instructions[index + 23], "IncludeManager");
        }
    }

    // Stores top-of-stack into static field.
    public class ReactorStsfldViaFieldInfoResolver : IPattern
    {
        public VMOpCode Translates => VMOpCode.Stsfld;

        public IList<CilOpCode> Pattern => new List<CilOpCode>
        {
            CilOpCodes.Ldarg_0,
            CilOpCodes.Ldfld,
            CilOpCodes.Unbox_Any,
            CilOpCodes.Stloc_S,
            CilOpCodes.Ldtoken,
            CilOpCodes.Ldsfld,
            CilOpCodes.Call,
            CilOpCodes.Ldsfld,
            CilOpCodes.Call,
            CilOpCodes.Ldloc_S,
            CilOpCodes.Ldsfld,
            CilOpCodes.Call,
            CilOpCodes.Stloc_S,
            CilOpCodes.Ldarg_0,
            CilOpCodes.Ldfld,
            CilOpCodes.Callvirt,
            CilOpCodes.Ldloc_S,
            CilOpCodes.Ldsfld,
            CilOpCodes.Call,
            CilOpCodes.Callvirt,
            CilOpCodes.Stloc_S,
            CilOpCodes.Ldloc_S,
            CilOpCodes.Ldnull,
            CilOpCodes.Ldloc_S,
            CilOpCodes.Ldsfld,
            CilOpCodes.Call,
            CilOpCodes.Ret
        };

        public bool Verify(MethodDefinition Method, int index)
        {
            var instructions = Method.CilMethodBody.Instructions.ToList();
            return index + 25 < instructions.Count &&
                   instructions[index + 22].OpCode == CilOpCodes.Ldnull &&
                   PatternHelpers.CallsMethodOnType(instructions[index + 25], "UpdateTransaction", "AnnotationModel");
        }
    }

    // Stores top-of-stack into instance field.
    public class ReactorStfldViaFieldInfoResolver : IPattern
    {
        public VMOpCode Translates => VMOpCode.Stfld;

        public IList<CilOpCode> Pattern => new List<CilOpCode>
        {
            CilOpCodes.Ldarg_0,
            CilOpCodes.Ldfld,
            CilOpCodes.Unbox_Any,
            CilOpCodes.Stloc_S,
            CilOpCodes.Ldtoken,
            CilOpCodes.Ldsfld,
            CilOpCodes.Call,
            CilOpCodes.Ldsfld,
            CilOpCodes.Call,
            CilOpCodes.Ldloc_S,
            CilOpCodes.Ldsfld,
            CilOpCodes.Call,
            CilOpCodes.Stloc_S,
            CilOpCodes.Ldarg_0,
            CilOpCodes.Ldfld,
            CilOpCodes.Callvirt,
            CilOpCodes.Ldloc_S,
            CilOpCodes.Ldsfld,
            CilOpCodes.Call,
            CilOpCodes.Callvirt,
            CilOpCodes.Stloc_S,
            CilOpCodes.Ldarg_0,
            CilOpCodes.Ldfld,
            CilOpCodes.Callvirt,
            CilOpCodes.Stloc_S
        };

        public bool Verify(MethodDefinition Method, int index)
        {
            var instructions = Method.CilMethodBody.Instructions.ToList();
            return PatternHelpers.ContainsMethodCallOnType(instructions, index, 120, "UpdateTransaction", "AnnotationModel") &&
                   PatternHelpers.ContainsOpCode(instructions, index, 120, CilOpCodes.Throw);
        }
    }

    // Unary negation helper.
    public class ReactorNegViaExternalChain : IPattern
    {
        public VMOpCode Translates => VMOpCode.Neg;

        public IList<CilOpCode> Pattern => new List<CilOpCode>
        {
            CilOpCodes.Ldarg_0,
            CilOpCodes.Ldfld,
            CilOpCodes.Ldarg_0,
            CilOpCodes.Ldfld,
            CilOpCodes.Callvirt,
            CilOpCodes.Castclass,
            CilOpCodes.Callvirt,
            CilOpCodes.Callvirt,
            CilOpCodes.Ret
        };

        public bool Verify(MethodDefinition Method, int index)
        {
            var instructions = Method.CilMethodBody.Instructions.ToList();
            return index + 7 < instructions.Count &&
                   PatternHelpers.CallsMethodNamed(instructions[index + 6], "DefineExternalChain") &&
                   PatternHelpers.CallsMethodNamed(instructions[index + 7], "IncludeManager");
        }
    }

    // Indirect branch by jump table operand.
    public class ReactorSwitchViaIntTable : IPattern
    {
        public VMOpCode Translates => VMOpCode.Switch;

        public IList<CilOpCode> Pattern => new List<CilOpCode>
        {
            CilOpCodes.Ldarg_0,
            CilOpCodes.Ldfld,
            CilOpCodes.Castclass,
            CilOpCodes.Stloc_S,
            CilOpCodes.Ldarg_0,
            CilOpCodes.Ldfld,
            CilOpCodes.Callvirt,
            CilOpCodes.Call,
            CilOpCodes.Stloc_S,
            CilOpCodes.Ldloc_S,
            CilOpCodes.Callvirt,
            CilOpCodes.Ldflda,
            CilOpCodes.Ldfld,
            CilOpCodes.Stloc_S
        };

        public bool Verify(MethodDefinition Method, int index)
        {
            var instructions = Method.CilMethodBody.Instructions.ToList();
            return PatternHelpers.ContainsMethodCall(instructions, index, 96, "DefineAutomatableElement") &&
                   PatternHelpers.ContainsOpCode(instructions, index, 96, CilOpCodes.Ldelem_I4) &&
                   PatternHelpers.ContainsOpCode(instructions, index, 96, CilOpCodes.Stfld);
        }
    }
}
