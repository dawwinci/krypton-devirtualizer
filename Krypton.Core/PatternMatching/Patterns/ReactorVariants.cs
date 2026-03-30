using System;
using System.Collections.Generic;
using System.Linq;
using AsmResolver.DotNet;
using AsmResolver.PE.DotNet.Cil;
using Krypton.Core.Architecture;

namespace Krypton.Core.PatternMatching.Patterns
{
    // Reactor-style handler: load local by index and push object via IncludeManager.
    public class ReactorLdlocViaTaskArray : IPattern
    {
        public VMOpCode Translates => VMOpCode.Ldloc;

        public IList<CilOpCode> Pattern => new List<CilOpCode>
        {
            CilOpCodes.Ldarg_0,
            CilOpCodes.Ldfld,
            CilOpCodes.Unbox_Any,
            CilOpCodes.Stloc_S,
            CilOpCodes.Ldarg_0,
            CilOpCodes.Ldfld,
            CilOpCodes.Ldloc_S,
            CilOpCodes.Ldelem_Ref,
            CilOpCodes.Stloc_S,
            CilOpCodes.Ldarg_0,
            CilOpCodes.Ldfld,
            CilOpCodes.Ldloc_S,
            CilOpCodes.Callvirt,
            CilOpCodes.Ret
        };

        public bool Verify(MethodDefinition Method, int index)
        {
            var instructions = Method.CilMethodBody.Instructions.ToList();
            return index + 12 < instructions.Count &&
                   PatternHelpers.CallsMethodNamed(instructions[index + 12], "IncludeManager");
        }
    }

    // Reactor-style handler: load argument by index and push object via IncludeManager.
    public class ReactorLdargViaCollectionArray : IPattern
    {
        public VMOpCode Translates => VMOpCode.Ldarg;

        public IList<CilOpCode> Pattern => new List<CilOpCode>
        {
            CilOpCodes.Ldarg_0,
            CilOpCodes.Ldfld,
            CilOpCodes.Unbox_Any,
            CilOpCodes.Stloc_S,
            CilOpCodes.Ldarg_0,
            CilOpCodes.Ldfld,
            CilOpCodes.Ldarg_0,
            CilOpCodes.Ldfld,
            CilOpCodes.Ldloc_S,
            CilOpCodes.Ldelem_Ref,
            CilOpCodes.Callvirt,
            CilOpCodes.Ret
        };

        public bool Verify(MethodDefinition Method, int index)
        {
            var instructions = Method.CilMethodBody.Instructions.ToList();
            return index + 10 < instructions.Count &&
                   PatternHelpers.CallsMethodNamed(instructions[index + 10], "IncludeManager");
        }
    }

    // Reactor variant where stloc handlers are expanded and include additional metadata lookups.
    public class ReactorStlocExpanded : IPattern
    {
        public VMOpCode Translates => VMOpCode.Stloc;

        public IList<CilOpCode> Pattern => new List<CilOpCode>
        {
            CilOpCodes.Ldarg_0,
            CilOpCodes.Ldfld,
            CilOpCodes.Unbox_Any,
            CilOpCodes.Stloc_S,
            CilOpCodes.Ldarg_0,
            CilOpCodes.Ldfld,
            CilOpCodes.Ldloc_S,
            CilOpCodes.Ldarg_0,
            CilOpCodes.Ldarg_0,
            CilOpCodes.Ldfld,
            CilOpCodes.Callvirt
        };

        public bool Verify(MethodDefinition Method, int index)
        {
            var instructions = Method.CilMethodBody.Instructions.ToList();
            return PatternHelpers.ContainsMethodCall(instructions, index, 64, "DefineAdvancedProxy") &&
                   PatternHelpers.ContainsOpCode(instructions, index, 64, CilOpCodes.Stelem_Ref);
        }
    }

    public class ReactorStlocConditionalProxy : IPattern
    {
        public VMOpCode Translates => VMOpCode.Stloc;

        public IList<CilOpCode> Pattern => new List<CilOpCode>
        {
            CilOpCodes.Ldarg_0,
            CilOpCodes.Ldfld,
            CilOpCodes.Unbox_Any,
            CilOpCodes.Stloc_S,
            CilOpCodes.Ldarg_0,
            CilOpCodes.Ldfld,
            CilOpCodes.Ldfld,
            CilOpCodes.Ldsfld,
            CilOpCodes.Call,
            CilOpCodes.Brfalse,
            CilOpCodes.Ldarg_0,
            CilOpCodes.Ldfld,
            CilOpCodes.Ldloc_S,
            CilOpCodes.Ldarg_0,
            CilOpCodes.Ldarg_0,
            CilOpCodes.Ldfld,
            CilOpCodes.Callvirt
        };

        public bool Verify(MethodDefinition Method, int index)
        {
            var instructions = Method.CilMethodBody.Instructions.ToList();
            return PatternHelpers.ContainsMethodCall(instructions, index, 64, "DefineAdvancedProxy") &&
                   PatternHelpers.ContainsOpCode(instructions, index, 64, CilOpCodes.Stelem_Ref);
        }
    }

    // Branch if top-of-stack is true; handler decrements VM instruction pointer and returns.
    public class ReactorBrTrueWithPredicates : IPattern
    {
        public VMOpCode Translates => VMOpCode.BrTrue;

        public IList<CilOpCode> Pattern => new List<CilOpCode>
        {
            CilOpCodes.Ldarg_0,
            CilOpCodes.Ldfld,
            CilOpCodes.Callvirt,
            CilOpCodes.Stloc_S,
            CilOpCodes.Ldloc_S,
            CilOpCodes.Brfalse,
            CilOpCodes.Ldloc_S,
            CilOpCodes.Callvirt,
            CilOpCodes.Brfalse,
            CilOpCodes.Ldarg_0,
            CilOpCodes.Ldarg_0,
            CilOpCodes.Ldfld,
            CilOpCodes.Unbox_Any,
            CilOpCodes.Ldc_I4_1,
            CilOpCodes.Sub,
            CilOpCodes.Stfld,
            CilOpCodes.Ret
        };

        public bool Verify(MethodDefinition Method, int index)
        {
            return PatternHelpers.EndsWithStateDecrementAndReturn(Method.CilMethodBody.Instructions.ToList(), index, 48);
        }
    }

    public class ReactorBrTrueDirectPredicate : IPattern
    {
        public VMOpCode Translates => VMOpCode.BrLessThan;

        public IList<CilOpCode> Pattern => new List<CilOpCode>
        {
            CilOpCodes.Ldarg_0,
            CilOpCodes.Ldfld,
            CilOpCodes.Callvirt,
            CilOpCodes.Ldarg_0,
            CilOpCodes.Ldfld,
            CilOpCodes.Callvirt,
            CilOpCodes.Callvirt,
            CilOpCodes.Brfalse,
            CilOpCodes.Ldarg_0,
            CilOpCodes.Ldarg_0,
            CilOpCodes.Ldfld,
            CilOpCodes.Unbox_Any,
            CilOpCodes.Ldc_I4_1,
            CilOpCodes.Sub,
            CilOpCodes.Stfld,
            CilOpCodes.Ret
        };

        public bool Verify(MethodDefinition Method, int index)
        {
            var instructions = Method.CilMethodBody.Instructions.ToList();
            if (index + 6 >= instructions.Count)
                return false;

            return PatternHelpers.EndsWithStateDecrementAndReturn(instructions, index, 48) &&
                   PatternHelpers.CallsAnyMethodNamed(instructions[index + 6], "DefineIntegratedModel");
        }
    }

    public class ReactorBrTrueFromExtendedChecker : IPattern
    {
        public VMOpCode Translates => VMOpCode.BrLessThan;

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
            CilOpCodes.Ldloc_S,
            CilOpCodes.Callvirt,
            CilOpCodes.Brfalse,
            CilOpCodes.Ldarg_0,
            CilOpCodes.Ldarg_0,
            CilOpCodes.Ldfld,
            CilOpCodes.Unbox_Any,
            CilOpCodes.Ldc_I4_1,
            CilOpCodes.Sub,
            CilOpCodes.Stfld,
            CilOpCodes.Ret
        };

        public bool Verify(MethodDefinition Method, int index)
        {
            var instructions = Method.CilMethodBody.Instructions.ToList();
            if (index + 9 >= instructions.Count)
                return false;

            return PatternHelpers.EndsWithStateDecrementAndReturn(instructions, index, 64) &&
                   PatternHelpers.CallsAnyMethodNamed(instructions[index + 9], "DisableField");
        }
    }

    // Reactor branch-false variant with an explicit normalization local.
    public class ReactorBrFalseWithLocalFlag : IPattern
    {
        public VMOpCode Translates => VMOpCode.BrFalse;

        public IList<CilOpCode> Pattern => new List<CilOpCode>
        {
            CilOpCodes.Ldc_I4_0,
            CilOpCodes.Stloc_S,
            CilOpCodes.Ldarg_0,
            CilOpCodes.Ldfld,
            CilOpCodes.Callvirt,
            CilOpCodes.Stloc_S,
            CilOpCodes.Ldloc_S,
            CilOpCodes.Brtrue,
            CilOpCodes.Ldc_I4_1,
            CilOpCodes.Stloc_S,
            CilOpCodes.Br,
            CilOpCodes.Ldloc_S,
            CilOpCodes.Callvirt,
            CilOpCodes.Ldc_I4_0,
            CilOpCodes.Ceq,
            CilOpCodes.Stloc_S,
            CilOpCodes.Ldloc_S,
            CilOpCodes.Brfalse
        };

        public bool Verify(MethodDefinition Method, int index)
        {
            return PatternHelpers.EndsWithStateDecrementAndReturn(Method.CilMethodBody.Instructions.ToList(), index, 80);
        }
    }

    public class ReactorLdstrPolicyFinder : IPattern
    {
        public VMOpCode Translates => VMOpCode.Ldstr;

        public IList<CilOpCode> Pattern => new List<CilOpCode>
        {
            CilOpCodes.Ldsfld,
            CilOpCodes.Callvirt,
            CilOpCodes.Brtrue,
            CilOpCodes.Ldtoken,
            CilOpCodes.Ldsfld,
            CilOpCodes.Call,
            CilOpCodes.Ldsfld,
            CilOpCodes.Call,
            CilOpCodes.Stloc_S,
            CilOpCodes.Ldarg_0,
            CilOpCodes.Ldfld,
            CilOpCodes.Ldloc_S,
            CilOpCodes.Ldarg_0,
            CilOpCodes.Ldfld,
            CilOpCodes.Unbox_Any,
            CilOpCodes.Ldc_I4,
            CilOpCodes.Or,
            CilOpCodes.Ldsfld,
            CilOpCodes.Call,
            CilOpCodes.Newobj,
            CilOpCodes.Callvirt,
            CilOpCodes.Ret
        };

        public bool Verify(MethodDefinition Method, int index)
        {
            var instructions = Method.CilMethodBody.Instructions.ToList();
            if (index + 20 >= instructions.Count)
                return false;

            if (!PatternHelpers.CallsMethodNamed(instructions[index + 20], "IncludeManager"))
                return false;

            if (!(instructions[index + 19].Operand is IMethodDescriptor descriptor))
                return false;

            var signature = descriptor.Signature ?? descriptor.Resolve()?.Signature;
            return signature?.ParameterTypes.Count == 1 &&
                   signature.ParameterTypes[0].FullName == "System.String";
        }
    }

    // Duplicate top stack value.
    public class ReactorDupViaReplaceTag : IPattern
    {
        public VMOpCode Translates => VMOpCode.Dup;

        public IList<CilOpCode> Pattern => new List<CilOpCode>
        {
            CilOpCodes.Ldarg_0,
            CilOpCodes.Ldfld,
            CilOpCodes.Ldarg_0,
            CilOpCodes.Ldfld,
            CilOpCodes.Callvirt,
            CilOpCodes.Callvirt,
            CilOpCodes.Ret
        };

        public bool Verify(MethodDefinition Method, int index)
        {
            var instructions = Method.CilMethodBody.Instructions.ToList();
            return index + 5 < instructions.Count &&
                   PatternHelpers.CallsMethodNamed(instructions[index + 4], "ReplaceTag") &&
                   PatternHelpers.CallsMethodNamed(instructions[index + 5], "IncludeManager");
        }
    }

    // Convert array object on stack to length wrapper.
    public class ReactorLdlenViaArrayInspector : IPattern
    {
        public VMOpCode Translates => VMOpCode.Ldlen;

        public IList<CilOpCode> Pattern => new List<CilOpCode>
        {
            CilOpCodes.Ldarg_0,
            CilOpCodes.Ldfld,
            CilOpCodes.Callvirt,
            CilOpCodes.Ldnull,
            CilOpCodes.Callvirt,
            CilOpCodes.Castclass,
            CilOpCodes.Stloc_S,
            CilOpCodes.Ldarg_0,
            CilOpCodes.Ldfld,
            CilOpCodes.Ldloc_S,
            CilOpCodes.Ldsfld,
            CilOpCodes.Call,
            CilOpCodes.Ldc_I4_5,
            CilOpCodes.Newobj,
            CilOpCodes.Callvirt,
            CilOpCodes.Ret
        };

        public bool Verify(MethodDefinition Method, int index)
        {
            var instructions = Method.CilMethodBody.Instructions.ToList();
            if (index + 14 >= instructions.Count)
                return false;

            return PatternHelpers.CallsMethodNamed(instructions[index + 14], "IncludeManager");
        }
    }

    // Obtain managed element address (array + index) with a typed operand token.
    public class ReactorLdelemaFromArrayAndIndex : IPattern
    {
        public VMOpCode Translates => VMOpCode.Ldelema;

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
            CilOpCodes.Pop,
            CilOpCodes.Ldarg_0,
            CilOpCodes.Ldfld,
            CilOpCodes.Callvirt,
            CilOpCodes.Call,
            CilOpCodes.Stloc_S
        };

        public bool Verify(MethodDefinition Method, int index)
        {
            var instructions = Method.CilMethodBody.Instructions.ToList();
            if (!PatternHelpers.ContainsMethodCall(instructions, index, 64, "TrackList") ||
                !PatternHelpers.ContainsMethodCall(instructions, index, 64, "IncludeManager"))
                return false;

            for (var i = index; i < Math.Min(index + 64, instructions.Count); i++)
            {
                if (instructions[i].OpCode != CilOpCodes.Newobj)
                    continue;
                if (!(instructions[i].Operand is IMethodDescriptor descriptor))
                    continue;

                var signature = descriptor.Signature ?? descriptor.Resolve()?.Signature;
                if (signature?.ParameterTypes.Count != 2)
                    continue;

                var first = signature.ParameterTypes[0].FullName;
                var second = signature.ParameterTypes[1].FullName;
                if (string.Equals(first, "System.Int32", StringComparison.Ordinal) &&
                    string.Equals(second, "System.Array", StringComparison.Ordinal))
                    return true;
            }

            return false;
        }
    }

    // Load value through typed managed address.
    public class ReactorLdobjFromManagedReference : IPattern
    {
        public VMOpCode Translates => VMOpCode.Ldobj;

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
            CilOpCodes.Isinst,
            CilOpCodes.Dup,
            CilOpCodes.Brtrue,
            CilOpCodes.Newobj,
            CilOpCodes.Throw
        };

        public bool Verify(MethodDefinition Method, int index)
        {
            var instructions = Method.CilMethodBody.Instructions.ToList();
            return PatternHelpers.ContainsMethodCall(instructions, index, 96, "DefineExpandableTester") &&
                   PatternHelpers.ContainsMethodCall(instructions, index, 96, "IncludeManager") &&
                   !PatternHelpers.ContainsMethodCall(instructions, index, 96, "EnforceMonoModel");
        }
    }

    // Store value through typed managed address.
    public class ReactorStobjViaManagedReference : IPattern
    {
        public VMOpCode Translates => VMOpCode.Stobj;

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
            CilOpCodes.Stloc_S
        };

        public bool Verify(MethodDefinition Method, int index)
        {
            var instructions = Method.CilMethodBody.Instructions.ToList();
            return PatternHelpers.ContainsMethodCall(instructions, index, 96, "EnforceMonoModel");
        }
    }
}
