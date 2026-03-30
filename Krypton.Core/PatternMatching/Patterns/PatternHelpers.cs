using System;
using System.Collections.Generic;
using System.Linq;
using AsmResolver.DotNet;
using AsmResolver.DotNet.Code.Cil;
using AsmResolver.PE.DotNet.Cil;

namespace Krypton.Core.PatternMatching.Patterns
{
    internal static class PatternHelpers
    {
        public static bool CallsMethodNamed(CilInstruction instruction, string methodName)
        {
            if (instruction == null)
                return false;

            if (instruction.OpCode != CilOpCodes.Call && instruction.OpCode != CilOpCodes.Callvirt)
                return false;

            if (!(instruction.Operand is IMethodDescriptor descriptor))
                return false;

            return string.Equals(descriptor.Name?.ToString(), methodName, StringComparison.Ordinal);
        }

        public static bool CalleeContainsOpCode(CilInstruction instruction, CilCode code)
        {
            return CalleeContainsOpCode(null, instruction, code, maxDepth: 3);
        }

        public static bool CalleeContainsOpCode(CilInstruction instruction, CilCode code, int maxDepth)
        {
            return CalleeContainsOpCode(null, instruction, code, maxDepth);
        }

        public static bool CalleeContainsOpCode(
            MethodDefinition caller,
            CilInstruction instruction,
            CilCode code,
            int maxDepth)
        {
            if (!TryGetCallDescriptor(instruction, out var descriptor))
                return false;

            var roots = ResolveCandidateMethods(caller?.Module, descriptor).ToList();
            if (roots.Count == 0)
                return false;

            var visited = new HashSet<MethodDefinition>();
            var depthLimit = Math.Max(maxDepth, 0);
            for (var i = 0; i < roots.Count; i++)
            {
                if (MethodContainsOpCodeRecursive(
                        caller?.Module ?? roots[i].Module,
                        roots[i],
                        code,
                        0,
                        depthLimit,
                        visited))
                {
                    return true;
                }
            }

            return false;
        }

        public static bool CalleeHasSignature(
            CilInstruction instruction,
            string returnTypeFullName,
            params string[] parameterTypeFullNames)
        {
            if (!TryGetCallDescriptor(instruction, out var descriptor))
                return false;

            var signature = descriptor.Signature ?? descriptor.Resolve()?.Signature;
            if (signature == null)
                return false;

            if (!string.Equals(signature.ReturnType?.FullName, returnTypeFullName, StringComparison.Ordinal))
                return false;

            if (parameterTypeFullNames == null)
                return signature.ParameterTypes.Count == 0;

            if (signature.ParameterTypes.Count != parameterTypeFullNames.Length)
                return false;

            for (var i = 0; i < parameterTypeFullNames.Length; i++)
            {
                if (!string.Equals(signature.ParameterTypes[i].FullName, parameterTypeFullNames[i], StringComparison.Ordinal))
                    return false;
            }

            return true;
        }

        public static bool CalleeLooksLikeIntLengthGetter(CilInstruction instruction)
        {
            if (!TryGetCallDescriptor(instruction, out var descriptor))
                return false;

            var signature = descriptor.Signature ?? descriptor.Resolve()?.Signature;
            if (signature == null)
                return false;

            if (signature.ParameterTypes.Count != 0 ||
                !string.Equals(signature.ReturnType?.FullName, "System.Int32", StringComparison.Ordinal))
            {
                return false;
            }

            var methodName = descriptor.Name?.ToString() ?? string.Empty;
            if (methodName.StartsWith("get_", StringComparison.Ordinal))
                return true;

            var declaring = descriptor.DeclaringType?.FullName ?? descriptor.Resolve()?.DeclaringType?.FullName ?? string.Empty;
            return declaring.IndexOf("Array", StringComparison.OrdinalIgnoreCase) >= 0 ||
                   declaring.IndexOf("Collection", StringComparison.OrdinalIgnoreCase) >= 0 ||
                   declaring.IndexOf("List", StringComparison.OrdinalIgnoreCase) >= 0;
        }

        public static bool CallsAnyMethodNamed(CilInstruction instruction, params string[] methodNames)
        {
            if (instruction == null || methodNames == null || methodNames.Length == 0)
                return false;

            if (instruction.OpCode != CilOpCodes.Call && instruction.OpCode != CilOpCodes.Callvirt)
                return false;

            if (!(instruction.Operand is IMethodDescriptor descriptor))
                return false;

            var name = descriptor.Name?.ToString();
            if (string.IsNullOrEmpty(name))
                return false;

            for (var i = 0; i < methodNames.Length; i++)
            {
                if (string.Equals(name, methodNames[i], StringComparison.Ordinal))
                    return true;
            }

            return false;
        }

        public static bool CallsMethodOnType(CilInstruction instruction, string methodName, string declaringTypeName)
        {
            if (instruction == null)
                return false;

            if (instruction.OpCode != CilOpCodes.Call && instruction.OpCode != CilOpCodes.Callvirt)
                return false;

            if (!(instruction.Operand is IMethodDescriptor descriptor))
                return false;

            if (!string.Equals(descriptor.Name?.ToString(), methodName, StringComparison.Ordinal))
                return false;

            var declaringType = descriptor.DeclaringType?.FullName ?? descriptor.Resolve()?.DeclaringType?.FullName;
            if (string.IsNullOrEmpty(declaringType))
                return false;

            return string.Equals(declaringType, declaringTypeName, StringComparison.Ordinal) ||
                   string.Equals(descriptor.DeclaringType?.Name?.ToString(), declaringTypeName, StringComparison.Ordinal);
        }

        public static bool ContainsMethodCall(
            IReadOnlyList<CilInstruction> instructions,
            int startIndex,
            int maxDistance,
            string methodName)
        {
            var end = Math.Min(instructions.Count, startIndex + maxDistance);
            for (var i = startIndex; i < end; i++)
            {
                if (CallsMethodNamed(instructions[i], methodName))
                    return true;
                if (instructions[i].OpCode == CilOpCodes.Ret)
                    break;
            }

            return false;
        }

        public static bool ContainsMethodCallOnType(
            IReadOnlyList<CilInstruction> instructions,
            int startIndex,
            int maxDistance,
            string methodName,
            string declaringTypeName)
        {
            var end = Math.Min(instructions.Count, startIndex + maxDistance);
            for (var i = startIndex; i < end; i++)
            {
                if (CallsMethodOnType(instructions[i], methodName, declaringTypeName))
                    return true;
                if (instructions[i].OpCode == CilOpCodes.Ret)
                    break;
            }

            return false;
        }

        public static bool ContainsOpCode(
            IReadOnlyList<CilInstruction> instructions,
            int startIndex,
            int maxDistance,
            CilOpCode opCode)
        {
            var end = Math.Min(instructions.Count, startIndex + maxDistance);
            for (var i = startIndex; i < end; i++)
            {
                if (instructions[i].OpCode == opCode)
                    return true;
                if (instructions[i].OpCode == CilOpCodes.Ret)
                    break;
            }

            return false;
        }

        public static bool EndsWithStateDecrementAndReturn(
            IReadOnlyList<CilInstruction> instructions,
            int startIndex,
            int maxDistance)
        {
            var end = Math.Min(instructions.Count, startIndex + maxDistance);
            var sawSub = false;
            var sawStoreField = false;

            for (var i = startIndex; i < end; i++)
            {
                var opCode = instructions[i].OpCode;
                if (opCode == CilOpCodes.Sub)
                    sawSub = true;
                else if (opCode == CilOpCodes.Stfld)
                    sawStoreField = true;
                else if (opCode == CilOpCodes.Ret)
                    return sawSub && sawStoreField;
            }

            return false;
        }

        public static bool IsIntConstant(CilInstruction instruction, int value)
        {
            if (instruction == null)
                return false;

            switch (instruction.OpCode.Code)
            {
                case CilCode.Ldc_I4_M1:
                    return value == -1;
                case CilCode.Ldc_I4_0:
                    return value == 0;
                case CilCode.Ldc_I4_1:
                    return value == 1;
                case CilCode.Ldc_I4_2:
                    return value == 2;
                case CilCode.Ldc_I4_3:
                    return value == 3;
                case CilCode.Ldc_I4_4:
                    return value == 4;
                case CilCode.Ldc_I4_5:
                    return value == 5;
                case CilCode.Ldc_I4_6:
                    return value == 6;
                case CilCode.Ldc_I4_7:
                    return value == 7;
                case CilCode.Ldc_I4_8:
                    return value == 8;
                case CilCode.Ldc_I4:
                case CilCode.Ldc_I4_S:
                    return Convert.ToInt32(instruction.Operand) == value;
                default:
                    return false;
            }
        }

        private static bool TryGetCallDescriptor(CilInstruction instruction, out IMethodDescriptor descriptor)
        {
            descriptor = null;
            if (instruction == null)
                return false;

            if (instruction.OpCode != CilOpCodes.Call && instruction.OpCode != CilOpCodes.Callvirt)
                return false;

            descriptor = instruction.Operand as IMethodDescriptor;
            return descriptor != null;
        }

        private static bool MethodContainsOpCodeRecursive(
            ModuleDefinition module,
            MethodDefinition method,
            CilCode code,
            int depth,
            int maxDepth,
            HashSet<MethodDefinition> visited)
        {
            if (method == null || !visited.Add(method))
                return false;

            var body = method.CilMethodBody;
            if (body == null || body.Instructions.Count == 0)
                return false;

            if (TryResolveByDirectOperation(body, code, out var directResult))
                return directResult;

            if (depth >= maxDepth)
                return false;

            for (var i = 0; i < body.Instructions.Count; i++)
            {
                var instruction = body.Instructions[i];
                if (!TryGetCallDescriptor(instruction, out var descriptor))
                    continue;

                foreach (var callee in ResolveCandidateMethods(module, descriptor))
                {
                    if (MethodContainsOpCodeRecursive(module, callee, code, depth + 1, maxDepth, visited))
                        return true;
                }
            }

            return false;
        }

        private static bool TryResolveByDirectOperation(CilMethodBody body, CilCode targetCode, out bool result)
        {
            result = false;
            if (body == null || body.Instructions.Count == 0)
                return false;

            var relatedCodes = GetRelatedCodes(targetCode);
            var sawAnyRelated = false;
            for (var i = 0; i < body.Instructions.Count; i++)
            {
                var code = body.Instructions[i].OpCode.Code;
                if (!relatedCodes.Contains(code))
                    continue;

                sawAnyRelated = true;
                if (code == targetCode)
                {
                    result = true;
                    return true;
                }
            }

            if (sawAnyRelated)
            {
                result = false;
                return true;
            }

            return false;
        }

        private static IReadOnlyCollection<CilCode> GetRelatedCodes(CilCode targetCode)
        {
            switch (targetCode)
            {
                case CilCode.Add:
                case CilCode.Sub:
                case CilCode.Xor:
                case CilCode.Shl:
                case CilCode.Shr:
                    return new[] { CilCode.Add, CilCode.Sub, CilCode.Xor, CilCode.Shl, CilCode.Shr };
                case CilCode.Not:
                    return new[] { CilCode.Not };
                case CilCode.Conv_I4:
                case CilCode.Conv_I8:
                case CilCode.Conv_U1:
                    return new[] { CilCode.Conv_I4, CilCode.Conv_I8, CilCode.Conv_U1 };
                default:
                    return new[] { targetCode };
            }
        }

        private static IEnumerable<MethodDefinition> ResolveCandidateMethods(
            ModuleDefinition module,
            IMethodDescriptor descriptor)
        {
            var seen = new HashSet<MethodDefinition>();
            var resolved = descriptor.Resolve();
            if (resolved != null && seen.Add(resolved))
                yield return resolved;

            var declaringType = descriptor.DeclaringType?.Resolve();
            var signature = descriptor.Signature ?? resolved?.Signature;
            var expectedReturnType = signature?.ReturnType?.FullName;
            var expectedParameterTypes = signature?.ParameterTypes.Select(p => p.FullName).ToArray();
            if (declaringType != null)
            {
                foreach (var method in declaringType.Methods)
                {
                    if (!LooksLikeMethodMatch(method, descriptor.Name?.ToString(), expectedReturnType, expectedParameterTypes))
                        continue;
                    if (seen.Add(method))
                        yield return method;
                }
            }

            if (module == null)
                yield break;

            foreach (var type in module.GetAllTypes())
            {
                foreach (var method in type.Methods)
                {
                    if (!LooksLikeMethodMatch(method, descriptor.Name?.ToString(), expectedReturnType, expectedParameterTypes))
                        continue;
                    if (seen.Add(method))
                        yield return method;
                }
            }
        }

        private static bool LooksLikeMethodMatch(
            MethodDefinition method,
            string targetName,
            string expectedReturnType,
            IReadOnlyList<string> expectedParameterTypes)
        {
            if (method == null || string.IsNullOrEmpty(targetName))
                return false;
            if (!string.Equals(method.Name, targetName, StringComparison.Ordinal))
                return false;
            if (expectedParameterTypes == null || method.Signature == null)
                return true;
            if (method.Signature.ParameterTypes.Count != expectedParameterTypes.Count)
                return false;

            if (!string.IsNullOrEmpty(expectedReturnType) &&
                !string.Equals(method.Signature.ReturnType?.FullName, expectedReturnType, StringComparison.Ordinal))
            {
                return false;
            }

            for (var i = 0; i < method.Signature.ParameterTypes.Count; i++)
            {
                if (!string.Equals(method.Signature.ParameterTypes[i].FullName, expectedParameterTypes[i], StringComparison.Ordinal))
                    return false;
            }

            return true;
        }
    }
}
