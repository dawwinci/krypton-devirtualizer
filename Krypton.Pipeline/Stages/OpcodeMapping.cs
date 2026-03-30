using System.Collections.Generic;
using System.Linq;
using System;
using AsmResolver.DotNet;
using AsmResolver.PE.DotNet.Cil;
using Krypton.Core;
using Krypton.Core.Architecture;
using Krypton.Core.PatternMatching;

namespace Krypton.Pipeline.Stages
{
    public class OpcodeMapping : IStage
    {
        public string Name => nameof(OpcodeMapping);

        public void Run(DevirtualizationCtx Ctx)
        {
            Ctx.PatternMatcher = new PatternMatcher();

            var opcodeHandlerMethod = FindOpCodeMethod(Ctx.Module);
            if (opcodeHandlerMethod == null)
                throw new DevirtualizationException("Could not locate Opcode Handler method.");
            Ctx.OpcodeHandlerMethod = opcodeHandlerMethod;
            Ctx.Options.Logger.Success($"Found method {opcodeHandlerMethod.Name} that contains Opcode Handlers!");

            var switchOpCode = opcodeHandlerMethod.CilMethodBody.Instructions.First(q => q.OpCode == CilOpCodes.Switch);

            var values = (List<ICilLabel>) switchOpCode.Operand;
            Ctx.OpcodeHandlerIndices = new Dictionary<int, int>();

            for (var i = 0; i < values.Count; i++)
            {
                var instructionLabel = (CilInstructionLabel) values[i];
                var index = opcodeHandlerMethod.CilMethodBody.Instructions.IndexOf(instructionLabel.Instruction);
                Ctx.OpcodeHandlerIndices[i] = index;
                var opCode = Ctx.PatternMatcher.FindOpCode(opcodeHandlerMethod, index);
                if (opCode != VMOpCode.Nop)
                    Ctx.PatternMatcher.SetOpCodeValue(opCode, i);
                if (string.Equals(
                        Environment.GetEnvironmentVariable("KRYPTON_LOG_VM_MAP"),
                        "1",
                        StringComparison.Ordinal))
                    Ctx.Options.Logger.Info($"vm 0x{i:X2} -> {opCode} (handler index {index})");
            }

            Ctx.Options.Logger.Info(
                $"Switch handlers: {values.Count} | mapped VM opcodes: {Ctx.PatternMatcher.GetMappedCount()}");
        }

        private MethodDefinition FindOpCodeMethod(ModuleDefinition Module)
        {
            foreach (var type in Module.GetAllTypes())
            {
                var method = type.Methods.FirstOrDefault(q =>
                    q.IsIL && q.CilMethodBody != null && q.CilMethodBody.Instructions != null &&
                    q.CilMethodBody.Instructions.Count >= 3200 &&
                    q.CilMethodBody.Instructions.Count(d => d.OpCode == CilOpCodes.Switch) == 1);
                if (method != null) return method;
            }

            return null;
        }
    }
}
