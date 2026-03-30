using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection.Metadata;
using System.Reflection.Metadata.Ecma335;
using System.Reflection.PortableExecutable;
using AsmResolver.DotNet;
using AsmResolver.DotNet.Code.Cil;
using AsmResolver.DotNet.Signatures.Types;
using AsmResolver.PE.DotNet.Cil;
using Krypton.Core;
using Krypton.Core.Architecture;

namespace Krypton.Pipeline.Stages
{
    public class MethodRecompiling : IStage
    {
        public string Name => nameof(MethodRecompiling);

        public void Run(DevirtualizationCtx Ctx)
        {
            foreach (var method in Ctx.VirtualizedMethods)
            {
                var unknownCount = method.MethodBody.Instructions.Count(q => q.OpCode == VMOpCode.Nop);
                if (unknownCount > 0)
                {
                    Ctx.Options.Logger.Warning(
                        $"Skipping recompilation for {method.Parent.FullName} because {unknownCount} VM instructions are still unknown.");
                    method.RecompiledBody = null;
                    continue;
                }

                try
                {
                    method.RecompiledBody = RecompileMethod(Ctx, method);
                    Ctx.Options.Logger.Info($"Recompiled method body for {method.Parent.FullName}");
                }
                catch (Exception ex)
                {
                    method.RecompiledBody = null;
                    Ctx.Options.Logger.Warning(
                        $"Recompilation failed for {method.Parent.FullName}: {ex.Message}");
                }
            }
        }

        private CilMethodBody RecompileMethod(DevirtualizationCtx ctx, VMMethod vmMethod)
        {
            if (vmMethod.Parent == null)
                throw new DevirtualizationException("VM method has no parent method.");

            var body = new CilMethodBody(vmMethod.Parent)
            {
                InitializeLocals = true,
                ComputeMaxStackOnBuild = true
            };

            var localTypes = InferLocalTypes(ctx, vmMethod);
            if (string.Equals(Environment.GetEnvironmentVariable("KRYPTON_LOG_LOCAL_TYPES"), "1", StringComparison.Ordinal))
            {
                var summary = string.Join(", ", localTypes.Select(t => t?.FullName ?? "<null>"));
                ctx.Options.Logger.Info($"Local type inference: {summary}");
            }
            var locals = new List<CilLocalVariable>(localTypes.Count);
            foreach (var localType in localTypes)
            {
                var local = new CilLocalVariable(localType);
                body.LocalVariables.Add(local);
                locals.Add(local);
            }

            var fixups = new List<(CilInstruction instruction, int targetOffset)>();
            var switchFixups = new List<(CilInstruction instruction, int[] targets)>();
            foreach (var vmInstruction in vmMethod.MethodBody.Instructions)
            {
                try
                {
                    var translated = TranslateInstruction(ctx, vmMethod, vmInstruction, locals, fixups, switchFixups);
                    body.Instructions.Add(translated);
                }
                catch (Exception ex)
                {
                    throw new DevirtualizationException(
                        $"Failed to translate VM instruction offset {vmInstruction.Offset} (vm:0x{vmInstruction.VmByte:X2}, op:{vmInstruction.OpCode}, operand:{vmInstruction.Operand ?? "<null>"}): {ex.Message}");
                }
            }

            foreach (var fixup in fixups)
            {
                if (fixup.targetOffset < 0 || fixup.targetOffset >= body.Instructions.Count)
                    throw new DevirtualizationException($"Invalid branch target offset {fixup.targetOffset}.");

                var targetInstruction = body.Instructions[fixup.targetOffset];
                fixup.instruction.Operand = new CilInstructionLabel(targetInstruction);
            }

            foreach (var switchFixup in switchFixups)
            {
                var labels = new List<ICilLabel>(switchFixup.targets.Length);
                for (var i = 0; i < switchFixup.targets.Length; i++)
                {
                    var targetOffset = switchFixup.targets[i];
                    if (targetOffset < 0 || targetOffset >= body.Instructions.Count)
                        throw new DevirtualizationException($"Invalid switch target offset {targetOffset}.");

                    labels.Add(new CilInstructionLabel(body.Instructions[targetOffset]));
                }

                switchFixup.instruction.Operand = labels;
            }

            ApplyExceptionHandlers(vmMethod, body);
            return body;
        }

        private List<TypeSignature> InferLocalTypes(DevirtualizationCtx ctx, VMMethod vmMethod)
        {
            var maxLocalIndex = -1;
            foreach (var instruction in vmMethod.MethodBody.Instructions)
            {
                if ((instruction.OpCode == VMOpCode.Stloc || instruction.OpCode == VMOpCode.Ldloc) &&
                    instruction.Operand is int index &&
                    index > maxLocalIndex)
                    maxLocalIndex = index;
            }

            var localCount = Math.Max(vmMethod.MethodBody.Locals.Count, maxLocalIndex + 1);
            var types = new List<TypeSignature>(localCount);
            for (var i = 0; i < localCount; i++)
            {
                if (i < vmMethod.MethodBody.Locals.Count)
                    types.Add(ToTypeSignature(ctx, vmMethod.MethodBody.Locals[i]));
                else
                    types.Add(ctx.Module.CorLibTypeFactory.Object);
            }

            for (var i = 0; i < vmMethod.MethodBody.Instructions.Count; i++)
            {
                var instruction = vmMethod.MethodBody.Instructions[i];
                if (instruction.OpCode != VMOpCode.Stloc || !(instruction.Operand is int localIndex))
                    continue;

                if (localIndex < 0 || localIndex >= types.Count || i == 0)
                    continue;

                var inferred = InferFromProducer(ctx, vmMethod.MethodBody.Instructions[i - 1]);
                if (inferred != null &&
                    (types[localIndex] == null ||
                     types[localIndex].FullName == ctx.Module.CorLibTypeFactory.Object.FullName))
                    types[localIndex] = inferred;
            }

            return types;
        }

        private TypeSignature ToTypeSignature(DevirtualizationCtx ctx, ITypeDescriptor descriptor)
        {
            if (descriptor == null)
                return ctx.Module.CorLibTypeFactory.Object;

            if (descriptor is TypeSignature signature)
                return signature;

            if (descriptor is ITypeDefOrRef typeDefOrRef)
                return new TypeDefOrRefSignature(typeDefOrRef);

            return ctx.Module.CorLibTypeFactory.Object;
        }

        private TypeSignature InferFromProducer(DevirtualizationCtx ctx, VMInstruction producer)
        {
            switch (producer.OpCode)
            {
                case VMOpCode.Ldc_I4:
                case VMOpCode.Conv_I4:
                case VMOpCode.Ldlen:
                case VMOpCode.Ldelem_U1:
                case VMOpCode.Add:
                case VMOpCode.Xor:
                case VMOpCode.Shl:
                case VMOpCode.Shr:
                case VMOpCode.Sub:
                case VMOpCode.Neg:
                case VMOpCode.Conv_U1:
                case VMOpCode.Not:
                    return ctx.Module.CorLibTypeFactory.Int32;
                case VMOpCode.Conv_I8:
                    return ctx.Module.CorLibTypeFactory.Int64;
                case VMOpCode.Ldnull:
                    return ctx.Module.CorLibTypeFactory.Object;
                case VMOpCode.Ldstr:
                    return ctx.Module.CorLibTypeFactory.String;
                case VMOpCode.Newarr:
                {
                    var elementType = ResolveTypeFromToken(ctx, producer.Operand);
                    return elementType == null
                        ? null
                        : new SzArrayTypeSignature(new TypeDefOrRefSignature(elementType));
                }
                case VMOpCode.Newobj:
                {
                    var descriptor = ResolveMethodDescriptor(ctx, producer.Operand) as IMethodDefOrRef;
                    if (descriptor?.DeclaringType == null)
                        return null;
                    return new TypeDefOrRefSignature(descriptor.DeclaringType);
                }
                case VMOpCode.Call:
                case VMOpCode.Callvirt:
                {
                    var descriptor = ResolveMethodDescriptor(ctx, producer.Operand);
                    return ResolveCallReturnType(descriptor);
                }
                case VMOpCode.Ldsfld:
                {
                    var field = ResolveFieldDescriptor(ctx, producer.Operand);
                    return field.Signature?.FieldType ?? field.Resolve()?.Signature?.FieldType;
                }
                case VMOpCode.Ldfld:
                {
                    var field = ResolveFieldDescriptor(ctx, producer.Operand);
                    return field.Signature?.FieldType ?? field.Resolve()?.Signature?.FieldType;
                }
                default:
                    return null;
            }
        }

        private TypeSignature ResolveCallReturnType(IMethodDescriptor descriptor)
        {
            if (descriptor == null)
                return null;

            if (descriptor is AsmResolver.DotNet.MethodSpecification methodSpec)
            {
                var baseReturnType = methodSpec.Method?.Signature?.ReturnType;
                return SubstituteMethodGenericArguments(baseReturnType, methodSpec.Signature?.TypeArguments);
            }

            return descriptor.Signature?.ReturnType;
        }

        private TypeSignature SubstituteMethodGenericArguments(
            TypeSignature signature,
            IList<TypeSignature> methodTypeArguments)
        {
            if (signature == null)
                return null;

            if (signature is GenericParameterSignature genericParameter &&
                genericParameter.ParameterType == GenericParameterType.Method &&
                methodTypeArguments != null &&
                genericParameter.Index >= 0 &&
                genericParameter.Index < methodTypeArguments.Count)
                return methodTypeArguments[genericParameter.Index];

            if (signature is SzArrayTypeSignature szArray)
            {
                var baseType = SubstituteMethodGenericArguments(szArray.BaseType, methodTypeArguments);
                if (baseType == null || ReferenceEquals(baseType, szArray.BaseType))
                    return signature;
                return new SzArrayTypeSignature(baseType);
            }

            if (signature is GenericInstanceTypeSignature genericInstance)
            {
                var changed = false;
                var substituted = new TypeSignature[genericInstance.TypeArguments.Count];
                for (var i = 0; i < genericInstance.TypeArguments.Count; i++)
                {
                    var current = genericInstance.TypeArguments[i];
                    substituted[i] = SubstituteMethodGenericArguments(current, methodTypeArguments);
                    if (!ReferenceEquals(substituted[i], current))
                        changed = true;
                }

                if (!changed)
                    return signature;

                return new GenericInstanceTypeSignature(genericInstance.GenericType, genericInstance.IsValueType, substituted);
            }

            return signature;
        }

        private CilInstruction TranslateInstruction(
            DevirtualizationCtx ctx,
            VMMethod vmMethod,
            VMInstruction instruction,
            IList<CilLocalVariable> locals,
            ICollection<(CilInstruction instruction, int targetOffset)> fixups,
            ICollection<(CilInstruction instruction, int[] targets)> switchFixups)
        {
            switch (instruction.OpCode)
            {
                case VMOpCode.Nop:
                    return new CilInstruction(CilOpCodes.Nop);
                case VMOpCode.Ldarg:
                    return BuildLdargInstruction(vmMethod, instruction.Operand);
                case VMOpCode.Ldloc:
                    return BuildLdlocInstruction(locals, instruction.Operand);
                case VMOpCode.Stloc:
                    return BuildStlocInstruction(locals, instruction.Operand);
                case VMOpCode.Ldsfld:
                    return new CilInstruction(CilOpCodes.Ldsfld, ResolveFieldDescriptor(ctx, instruction.Operand));
                case VMOpCode.Ldfld:
                    return new CilInstruction(CilOpCodes.Ldfld, ResolveFieldDescriptor(ctx, instruction.Operand));
                case VMOpCode.Stsfld:
                    return new CilInstruction(CilOpCodes.Stsfld, ResolveFieldDescriptor(ctx, instruction.Operand));
                case VMOpCode.Stfld:
                    return new CilInstruction(CilOpCodes.Stfld, ResolveFieldDescriptor(ctx, instruction.Operand));
                case VMOpCode.Ldc_I4:
                    return new CilInstruction(CilOpCodes.Ldc_I4, Convert.ToInt32(instruction.Operand));
                case VMOpCode.Ldelem_Ref:
                    return new CilInstruction(CilOpCodes.Ldelem_Ref);
                case VMOpCode.Ldelem_U1:
                    return new CilInstruction(CilOpCodes.Ldelem_U1);
                case VMOpCode.Stelem_Ref:
                    return new CilInstruction(CilOpCodes.Stelem_Ref);
                case VMOpCode.Stelem_I1:
                    return new CilInstruction(CilOpCodes.Stelem_I1);
                case VMOpCode.Ldstr:
                    return new CilInstruction(CilOpCodes.Ldstr, ResolveUserString(ctx, Convert.ToInt32(instruction.Operand)));
                case VMOpCode.Call:
                    return BuildCallInstruction(ctx, instruction.Operand, false);
                case VMOpCode.Callvirt:
                    return BuildCallInstruction(ctx, instruction.Operand, true);
                case VMOpCode.Newobj:
                    return new CilInstruction(CilOpCodes.Newobj, ResolveMethodDescriptor(ctx, instruction.Operand));
                case VMOpCode.Newarr:
                    return new CilInstruction(CilOpCodes.Newarr, ResolveTypeFromToken(ctx, instruction.Operand));
                case VMOpCode.Br:
                    return BuildUnconditionalBranch(vmMethod, instruction, fixups);
                case VMOpCode.BrTrue:
                {
                    var branch = new CilInstruction(CilOpCodes.Brtrue);
                    fixups.Add((branch, Convert.ToInt32(instruction.Operand)));
                    return branch;
                }
                case VMOpCode.BrLessThan:
                {
                    var branch = new CilInstruction(CilOpCodes.Blt_Un);
                    fixups.Add((branch, Convert.ToInt32(instruction.Operand)));
                    return branch;
                }
                case VMOpCode.BrFalse:
                {
                    var branch = new CilInstruction(CilOpCodes.Brfalse);
                    fixups.Add((branch, Convert.ToInt32(instruction.Operand)));
                    return branch;
                }
                case VMOpCode.Pop:
                    return new CilInstruction(CilOpCodes.Pop);
                case VMOpCode.Dup:
                    return new CilInstruction(CilOpCodes.Dup);
                case VMOpCode.Ldlen:
                    return new CilInstruction(CilOpCodes.Ldlen);
                case VMOpCode.Ldelema:
                    return new CilInstruction(CilOpCodes.Ldelema, ResolveTypeFromToken(ctx, instruction.Operand));
                case VMOpCode.Ldobj:
                    return BuildLdobjInstruction(ctx, instruction.Operand);
                case VMOpCode.Stobj:
                    return BuildStobjInstruction(ctx, instruction.Operand);
                case VMOpCode.Conv_I4:
                    return new CilInstruction(CilOpCodes.Conv_I4);
                case VMOpCode.Conv_I8:
                    return new CilInstruction(CilOpCodes.Conv_I8);
                case VMOpCode.Conv_U1:
                    return new CilInstruction(CilOpCodes.Conv_U1);
                case VMOpCode.Not:
                    return new CilInstruction(CilOpCodes.Not);
                case VMOpCode.Add:
                    return new CilInstruction(CilOpCodes.Add);
                case VMOpCode.Xor:
                    return new CilInstruction(CilOpCodes.Xor);
                case VMOpCode.Shl:
                    return new CilInstruction(CilOpCodes.Shl);
                case VMOpCode.Shr:
                    return new CilInstruction(CilOpCodes.Shr);
                case VMOpCode.Sub:
                    return new CilInstruction(CilOpCodes.Sub);
                case VMOpCode.Neg:
                    return new CilInstruction(CilOpCodes.Neg);
                case VMOpCode.Ldnull:
                    return new CilInstruction(CilOpCodes.Ldnull);
                case VMOpCode.Switch:
                {
                    if (!(instruction.Operand is int[] targets))
                        throw new DevirtualizationException("Expected Int32[] switch operand.");

                    var branch = new CilInstruction(CilOpCodes.Switch);
                    switchFixups.Add((branch, targets));
                    return branch;
                }
                case VMOpCode.Leave:
                    return new CilInstruction(CilOpCodes.Endfinally);
                case VMOpCode.Ret:
                    return new CilInstruction(CilOpCodes.Ret);
                default:
                    throw new DevirtualizationException($"Cannot recompile unsupported VM opcode: {instruction.OpCode}");
            }
        }

        private CilInstruction BuildUnconditionalBranch(
            VMMethod vmMethod,
            VMInstruction instruction,
            ICollection<(CilInstruction instruction, int targetOffset)> fixups)
        {
            var targetOffset = Convert.ToInt32(instruction.Operand);
            var opcode = ShouldUseLeave(vmMethod, instruction.Offset, targetOffset)
                ? CilOpCodes.Leave
                : CilOpCodes.Br;

            var branch = new CilInstruction(opcode);
            fixups.Add((branch, targetOffset));
            return branch;
        }

        private bool ShouldUseLeave(VMMethod vmMethod, int sourceOffset, int targetOffset)
        {
            foreach (var eh in vmMethod.MethodBody.ExceptionHandlers)
            {
                var sourceInTry = IsInsideRange(sourceOffset, eh.TryStart, eh.TryEnd);
                if (sourceInTry && !IsInsideRange(targetOffset, eh.TryStart, eh.TryEnd))
                    return true;

                var sourceInHandler = IsInsideRange(sourceOffset, eh.HandlerStart, eh.HandlerEnd);
                if (sourceInHandler && !IsInsideRange(targetOffset, eh.HandlerStart, eh.HandlerEnd))
                    return true;
            }

            return false;
        }

        private bool IsInsideRange(int offset, int start, int endInclusive)
        {
            return offset >= start && offset <= endInclusive;
        }

        private void ApplyExceptionHandlers(VMMethod vmMethod, CilMethodBody body)
        {
            foreach (var vmEh in vmMethod.MethodBody.ExceptionHandlers)
            {
                var cilEh = new CilExceptionHandler
                {
                    HandlerType = MapExceptionHandlerType(vmEh.EHType),
                    TryStart = GetInstructionAt(body, vmEh.TryStart, "try start"),
                    TryEnd = GetInstructionBoundary(body, vmEh.TryEnd + 1),
                    HandlerStart = GetInstructionAt(body, vmEh.HandlerStart, "handler start"),
                    HandlerEnd = GetInstructionBoundary(body, vmEh.HandlerEnd + 1)
                };

                switch (vmEh.EHType)
                {
                    case VMExceptionHandlerType.Catch:
                        cilEh.ExceptionType = ResolveExceptionType(vmEh.CatchType);
                        break;
                    case VMExceptionHandlerType.Filter:
                        cilEh.FilterStart = GetInstructionAt(body, vmEh.Filter, "filter start");
                        break;
                }

                body.ExceptionHandlers.Add(cilEh);
            }
        }

        private CilExceptionHandlerType MapExceptionHandlerType(VMExceptionHandlerType type)
        {
            return type switch
            {
                VMExceptionHandlerType.Catch => CilExceptionHandlerType.Exception,
                VMExceptionHandlerType.Filter => CilExceptionHandlerType.Filter,
                VMExceptionHandlerType.Finally => CilExceptionHandlerType.Finally,
                VMExceptionHandlerType.Fault => CilExceptionHandlerType.Fault,
                _ => throw new DevirtualizationException($"Unsupported exception handler type: {type}.")
            };
        }

        private ITypeDefOrRef ResolveExceptionType(ITypeDescriptor descriptor)
        {
            if (descriptor is ITypeDefOrRef typeDefOrRef)
                return typeDefOrRef;
            if (descriptor is TypeDefOrRefSignature typeDefOrRefSignature)
                return typeDefOrRefSignature.Type;

            throw new DevirtualizationException("Unsupported catch type descriptor.");
        }

        private ICilLabel GetInstructionAt(CilMethodBody body, int index, string markerName)
        {
            if (index < 0 || index >= body.Instructions.Count)
                throw new DevirtualizationException($"Invalid {markerName} index {index}.");

            return new CilInstructionLabel(body.Instructions[index]);
        }

        private ICilLabel GetInstructionBoundary(CilMethodBody body, int index)
        {
            if (index < 0 || index > body.Instructions.Count)
                throw new DevirtualizationException($"Invalid exception boundary index {index}.");

            return index == body.Instructions.Count
                ? null
                : new CilInstructionLabel(body.Instructions[index]);
        }

        private CilInstruction BuildLdargInstruction(VMMethod vmMethod, object operand)
        {
            var vmIndex = Convert.ToInt32(operand);
            var index = vmIndex;
            switch (index)
            {
                case 0:
                    return new CilInstruction(CilOpCodes.Ldarg_0);
                case 1:
                    return new CilInstruction(CilOpCodes.Ldarg_1);
                case 2:
                    return new CilInstruction(CilOpCodes.Ldarg_2);
                case 3:
                    return new CilInstruction(CilOpCodes.Ldarg_3);
                default:
                    return new CilInstruction(CilOpCodes.Ldarg, index);
            }
        }

        private CilInstruction BuildLdlocInstruction(IList<CilLocalVariable> locals, object operand)
        {
            var index = Convert.ToInt32(operand);
            if (index < 0 || index >= locals.Count)
                throw new DevirtualizationException($"Invalid ldloc index {index}.");

            switch (index)
            {
                case 0:
                    return new CilInstruction(CilOpCodes.Ldloc_0);
                case 1:
                    return new CilInstruction(CilOpCodes.Ldloc_1);
                case 2:
                    return new CilInstruction(CilOpCodes.Ldloc_2);
                case 3:
                    return new CilInstruction(CilOpCodes.Ldloc_3);
                default:
                    return new CilInstruction(CilOpCodes.Ldloc, locals[index]);
            }
        }

        private CilInstruction BuildStlocInstruction(IList<CilLocalVariable> locals, object operand)
        {
            var index = Convert.ToInt32(operand);
            if (index < 0 || index >= locals.Count)
                throw new DevirtualizationException($"Invalid stloc index {index}.");

            switch (index)
            {
                case 0:
                    return new CilInstruction(CilOpCodes.Stloc_0);
                case 1:
                    return new CilInstruction(CilOpCodes.Stloc_1);
                case 2:
                    return new CilInstruction(CilOpCodes.Stloc_2);
                case 3:
                    return new CilInstruction(CilOpCodes.Stloc_3);
                default:
                    return new CilInstruction(CilOpCodes.Stloc, locals[index]);
            }
        }

        private CilInstruction BuildCallInstruction(DevirtualizationCtx ctx, object operand, bool forceVirtualCall)
        {
            var descriptor = ResolveMethodDescriptor(ctx, operand);
            if (forceVirtualCall)
                return new CilInstruction(CilOpCodes.Callvirt, descriptor);

            var hasThis = descriptor.Signature?.HasThis == true;
            if (!hasThis && descriptor is AsmResolver.DotNet.MethodSpecification spec)
                hasThis = spec.Method?.Signature?.HasThis == true;

            var opcode = CilOpCodes.Call;
            if (hasThis)
            {
                var resolved = descriptor.Resolve();
                if (resolved == null ||
                    resolved.IsVirtual ||
                    resolved.DeclaringType?.IsInterface == true)
                {
                    opcode = CilOpCodes.Callvirt;
                }
            }

            return new CilInstruction(opcode, descriptor);
        }

        private IMethodDescriptor ResolveMethodDescriptor(DevirtualizationCtx ctx, object operand)
        {
            if (!(operand is int token))
                throw new DevirtualizationException("Expected method token operand.");

            var member = ctx.Module.LookupMember(token);
            if (member is IMethodDescriptor descriptor)
                return descriptor;

            throw new DevirtualizationException($"Token 0x{token:X8} is not a method descriptor.");
        }

        private IFieldDescriptor ResolveFieldDescriptor(DevirtualizationCtx ctx, object operand)
        {
            if (!(operand is int token))
                throw new DevirtualizationException("Expected field token operand.");

            var member = ctx.Module.LookupMember(token);
            if (member is IFieldDescriptor descriptor)
                return descriptor;

            throw new DevirtualizationException($"Token 0x{token:X8} is not a field descriptor.");
        }

        private ITypeDefOrRef ResolveTypeFromToken(DevirtualizationCtx ctx, object operand)
        {
            if (!(operand is int token))
                throw new DevirtualizationException("Expected type token operand.");

            var member = ctx.Module.LookupMember(token);
            if (member is ITypeDefOrRef type)
                return type;
            if (member is TypeSignature typeSignature && typeSignature is TypeDefOrRefSignature typeDefOrRefSignature)
                return typeDefOrRefSignature.Type;

            throw new DevirtualizationException($"Token 0x{token:X8} is not a type reference.");
        }

        private CilInstruction BuildLdobjInstruction(DevirtualizationCtx ctx, object operand)
        {
            var type = ResolveTypeFromToken(ctx, operand);
            switch (type.FullName)
            {
                case "System.SByte":
                    return new CilInstruction(CilOpCodes.Ldind_I1);
                case "System.Byte":
                case "System.Boolean":
                    return new CilInstruction(CilOpCodes.Ldind_U1);
                case "System.Int16":
                    return new CilInstruction(CilOpCodes.Ldind_I2);
                case "System.UInt16":
                case "System.Char":
                    return new CilInstruction(CilOpCodes.Ldind_U2);
                case "System.Int32":
                    return new CilInstruction(CilOpCodes.Ldind_I4);
                case "System.UInt32":
                    return new CilInstruction(CilOpCodes.Ldind_U4);
                case "System.Int64":
                case "System.UInt64":
                    return new CilInstruction(CilOpCodes.Ldind_I8);
                case "System.Single":
                    return new CilInstruction(CilOpCodes.Ldind_R4);
                case "System.Double":
                    return new CilInstruction(CilOpCodes.Ldind_R8);
                case "System.IntPtr":
                case "System.UIntPtr":
                    return new CilInstruction(CilOpCodes.Ldind_I);
                default:
                    return new CilInstruction(CilOpCodes.Ldobj, type);
            }
        }

        private CilInstruction BuildStobjInstruction(DevirtualizationCtx ctx, object operand)
        {
            var type = ResolveTypeFromToken(ctx, operand);
            switch (type.FullName)
            {
                case "System.SByte":
                case "System.Byte":
                case "System.Boolean":
                    return new CilInstruction(CilOpCodes.Stind_I1);
                case "System.Int16":
                case "System.UInt16":
                case "System.Char":
                    return new CilInstruction(CilOpCodes.Stind_I2);
                case "System.Int32":
                case "System.UInt32":
                    return new CilInstruction(CilOpCodes.Stind_I4);
                case "System.Int64":
                case "System.UInt64":
                    return new CilInstruction(CilOpCodes.Stind_I8);
                case "System.Single":
                    return new CilInstruction(CilOpCodes.Stind_R4);
                case "System.Double":
                    return new CilInstruction(CilOpCodes.Stind_R8);
                case "System.IntPtr":
                case "System.UIntPtr":
                    return new CilInstruction(CilOpCodes.Stind_I);
                default:
                    return new CilInstruction(CilOpCodes.Stobj, type);
            }
        }

        private string ResolveUserString(DevirtualizationCtx ctx, int offset)
        {
            try
            {
                using var fs = File.OpenRead(ctx.Options.FilePath);
                using var pe = new PEReader(fs);
                var mr = pe.GetMetadataReader();
                var handle = MetadataTokens.UserStringHandle(offset);
                return mr.GetUserString(handle);
            }
            catch
            {
                return string.Empty;
            }
        }
    }
}
