using System;
using System.Collections.Generic;
using System.Linq;
using AsmResolver.DotNet;
using AsmResolver.PE.DotNet.Cil;
using Krypton.Core.Architecture;

namespace Krypton.Core.PatternMatching.Patterns
{
    // Generic DUP handler: pop top value and push it back twice-equivalent to IL dup.
    public class ReactorDupViaPopPushPair : IPattern
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
            if (index + 5 >= instructions.Count)
                return false;

            if (!(instructions[index + 4].Operand is IMethodDescriptor popDescriptor))
                return false;
            if (!(instructions[index + 5].Operand is IMethodDescriptor pushDescriptor))
                return false;

            var popSignature = popDescriptor.Signature ?? popDescriptor.Resolve()?.Signature;
            var pushSignature = pushDescriptor.Signature ?? pushDescriptor.Resolve()?.Signature;
            if (popSignature == null || pushSignature == null)
                return false;

            return popSignature.ParameterTypes.Count == 0 &&
                   !string.Equals(popSignature.ReturnType?.FullName, "System.Void", StringComparison.Ordinal) &&
                   pushSignature.ParameterTypes.Count == 1 &&
                   string.Equals(pushSignature.ReturnType?.FullName, "System.Void", StringComparison.Ordinal);
        }
    }

    // Reactor branch variant using two temporary locals before comparing and decrementing VM IP.
    public class ReactorBrLessThanViaTempPredicate : IPattern
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
            CilOpCodes.Stloc_S,
            CilOpCodes.Ldloc_S,
            CilOpCodes.Ldloc_S,
            CilOpCodes.Callvirt,
            CilOpCodes.Stloc_S,
            CilOpCodes.Ldloc_S,
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
            if (index + 22 >= instructions.Count)
                return false;

            if (!PatternHelpers.EndsWithStateDecrementAndReturn(instructions, index, 64))
                return false;

            if (!(instructions[index + 11].Operand is IMethodDescriptor compareDescriptor))
                return false;

            var compareSignature = compareDescriptor.Signature ?? compareDescriptor.Resolve()?.Signature;
            return compareSignature?.ParameterTypes.Count == 1 &&
                   string.Equals(compareSignature.ReturnType?.FullName, "System.Boolean", StringComparison.Ordinal);
        }
    }

    // Reactor branch variant comparing two temporary values directly (no intermediate helper call).
    public class ReactorBrLessThanViaDirectTempCompare : IPattern
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
            CilOpCodes.Stloc_S,
            CilOpCodes.Ldloc_S,
            CilOpCodes.Ldloc_S,
            CilOpCodes.Callvirt,
            CilOpCodes.Stloc_S,
            CilOpCodes.Ldloc_S,
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
            if (index + 21 >= instructions.Count)
                return false;

            if (!PatternHelpers.EndsWithStateDecrementAndReturn(instructions, index, 64))
                return false;

            if (!(instructions[index + 10].Operand is IMethodDescriptor compareDescriptor))
                return false;

            var compareSignature = compareDescriptor.Signature ?? compareDescriptor.Resolve()?.Signature;
            return compareSignature?.ParameterTypes.Count == 1 &&
                   string.Equals(compareSignature.ReturnType?.FullName, "System.Boolean", StringComparison.Ordinal);
        }
    }

    // Alternate ldloc handler that wraps local index into a ctor argument.
    public class ReactorLdlocViaCtorIndexWrapper : IPattern
    {
        public VMOpCode Translates => VMOpCode.Ldloc;

        public IList<CilOpCode> Pattern => new List<CilOpCode>
        {
            CilOpCodes.Ldarg_0,
            CilOpCodes.Ldfld,
            CilOpCodes.Ldarg_0,
            CilOpCodes.Ldfld,
            CilOpCodes.Unbox_Any,
            CilOpCodes.Ldarg_0,
            CilOpCodes.Newobj,
            CilOpCodes.Callvirt,
            CilOpCodes.Ret
        };

        public bool Verify(MethodDefinition Method, int index)
        {
            var instructions = Method.CilMethodBody.Instructions.ToList();
            if (index + 7 >= instructions.Count)
                return false;

            if (!(instructions[index + 6].Operand is IMethodDescriptor ctorDescriptor))
                return false;
            if (!(instructions[index + 7].Operand is IMethodDescriptor pushDescriptor))
                return false;

            var ctorSignature = ctorDescriptor.Signature ?? ctorDescriptor.Resolve()?.Signature;
            var pushSignature = pushDescriptor.Signature ?? pushDescriptor.Resolve()?.Signature;
            if (ctorSignature == null || pushSignature == null)
                return false;

            return ctorSignature.ParameterTypes.Count == 2 &&
                   string.Equals(ctorSignature.ParameterTypes[0].FullName, "System.Int32", StringComparison.Ordinal) &&
                   pushSignature.ParameterTypes.Count == 1 &&
                   string.Equals(pushSignature.ReturnType?.FullName, "System.Void", StringComparison.Ordinal);
        }
    }

    // ldelem.ref implemented through System.Array::GetValue(index) then VM push.
    public class ReactorLdelemRefViaArrayGetValue : IPattern
    {
        public VMOpCode Translates => VMOpCode.Ldelem_Ref;

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
            CilOpCodes.Stloc_S,
            CilOpCodes.Ldloc_S,
            CilOpCodes.Ldloc_S,
            CilOpCodes.Callvirt,
            CilOpCodes.Ldflda,
            CilOpCodes.Ldfld,
            CilOpCodes.Callvirt
        };

        public bool Verify(MethodDefinition Method, int index)
        {
            var instructions = Method.CilMethodBody.Instructions.ToList();
            if (index + 17 >= instructions.Count)
                return false;

            var getValue = instructions[index + 17];
            return PatternHelpers.CallsMethodOnType(getValue, "GetValue", "System.Array") &&
                   PatternHelpers.CalleeHasSignature(getValue, "System.Object", "System.Int32");
        }
    }

    // stelem.ref implemented through System.Array::SetValue(value, index).
    public class ReactorStelemRefViaArraySetValue : IPattern
    {
        public VMOpCode Translates => VMOpCode.Stelem_Ref;

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
            CilOpCodes.Stloc_S,
            CilOpCodes.Ldloc_S,
            CilOpCodes.Callvirt,
            CilOpCodes.Callvirt,
            CilOpCodes.Stloc_S,
            CilOpCodes.Ldloc_S,
            CilOpCodes.Ldloc_S,
            CilOpCodes.Ldloc_S,
            CilOpCodes.Callvirt,
            CilOpCodes.Ldloc_S,
            CilOpCodes.Callvirt,
            CilOpCodes.Ldflda,
            CilOpCodes.Ldfld,
            CilOpCodes.Callvirt,
            CilOpCodes.Ret
        };

        public bool Verify(MethodDefinition Method, int index)
        {
            var instructions = Method.CilMethodBody.Instructions.ToList();
            if (index + 28 >= instructions.Count)
                return false;

            var setValue = instructions[index + 28];
            return PatternHelpers.CallsMethodOnType(setValue, "SetValue", "System.Array") &&
                   PatternHelpers.CalleeHasSignature(setValue, "System.Void", "System.Object", "System.Int32");
        }
    }

    // ldfld implemented via Module.ResolveField + FieldInfo.GetValue(object).
    public class ReactorLdfldViaResolveField : IPattern
    {
        public VMOpCode Translates => VMOpCode.Ldfld;

        public IList<CilOpCode> Pattern => new List<CilOpCode>
        {
            CilOpCodes.Ldarg_0,
            CilOpCodes.Ldfld,
            CilOpCodes.Unbox_Any,
            CilOpCodes.Stloc_S,
            CilOpCodes.Nop,
            CilOpCodes.Call,
            CilOpCodes.Call,
            CilOpCodes.Callvirt,
            CilOpCodes.Stloc_S,
            CilOpCodes.Ldloc_S,
            CilOpCodes.Ldloc_S,
            CilOpCodes.Callvirt,
            CilOpCodes.Stloc_S,
            CilOpCodes.Ldarg_0,
            CilOpCodes.Ldfld,
            CilOpCodes.Callvirt,
            CilOpCodes.Stloc_S,
            CilOpCodes.Ldloc_S,
            CilOpCodes.Ldnull,
            CilOpCodes.Callvirt,
            CilOpCodes.Stloc_S,
            CilOpCodes.Ldarg_0,
            CilOpCodes.Ldfld,
            CilOpCodes.Ldloc_S,
            CilOpCodes.Callvirt,
            CilOpCodes.Ldloc_S,
            CilOpCodes.Ldloc_S,
            CilOpCodes.Callvirt,
            CilOpCodes.Call,
            CilOpCodes.Callvirt,
            CilOpCodes.Ret
        };

        public bool Verify(MethodDefinition Method, int index)
        {
            var instructions = Method.CilMethodBody.Instructions.ToList();
            if (index + 29 >= instructions.Count)
                return false;

            var getModule = instructions[index + 7];
            var resolveField = instructions[index + 11];
            var getFieldType = instructions[index + 24];
            var getValue = instructions[index + 27];

            if (!PatternHelpers.CallsMethodOnType(getModule, "get_Module", "System.Type"))
                return false;
            if (!PatternHelpers.CallsMethodOnType(resolveField, "ResolveField", "System.Reflection.Module") ||
                !PatternHelpers.CalleeHasSignature(resolveField, "System.Reflection.FieldInfo", "System.Int32"))
                return false;
            if (!PatternHelpers.CallsMethodOnType(getFieldType, "get_FieldType", "System.Reflection.FieldInfo") ||
                !PatternHelpers.CalleeHasSignature(getFieldType, "System.Type"))
                return false;
            if (!PatternHelpers.CallsMethodOnType(getValue, "GetValue", "System.Reflection.FieldInfo") ||
                !PatternHelpers.CalleeHasSignature(getValue, "System.Object", "System.Object"))
                return false;

            if (!(instructions[index + 29].Operand is IMethodDescriptor pushDescriptor))
                return false;
            var pushSignature = pushDescriptor.Signature ?? pushDescriptor.Resolve()?.Signature;
            return pushSignature?.ParameterTypes.Count == 1 &&
                   string.Equals(pushSignature.ReturnType?.FullName, "System.Void", StringComparison.Ordinal);
        }
    }
}
