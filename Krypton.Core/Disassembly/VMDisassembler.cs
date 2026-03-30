using System;
using AsmResolver.DotNet;
using Krypton.Core.Architecture;

namespace Krypton.Core.Disassembly
{
    public class VMDisassembler
    {
        public VMDisassembler(DevirtualizationCtx Ctx)
        {
            this.Ctx = Ctx;
        }

        private DevirtualizationCtx Ctx { get; }

        public VMMethod DisassembleMethod(int methodKey)
        {
            var method = new VMMethod(methodKey);
            Ctx.Parser.Reader.BaseStream.Position = methodKey;

            var mdToken = Ctx.Parser.ReadEncryptedByte();
            var parentMethod = ((IMethodDescriptor) Ctx.Module.LookupMember(mdToken)).Resolve();
            method.Parent = parentMethod;

            var locals = Ctx.Parser.ReadEncryptedByte();
            var exceptionHandlers = Ctx.Parser.ReadEncryptedByte();
            var instructions = Ctx.Parser.ReadEncryptedByte();

            ReadLocals(method, locals);
            ReadExceptionHandlers(method, exceptionHandlers);
            ReadAllInstructions(method, instructions);

            return method;
        }

        public void ReadLocals(VMMethod method, int locals)
        {
            for (var i = 0; i < locals; i++)
            {
                var token = Ctx.Parser.ReadEncryptedByte();
                ITypeDescriptor localType = null;
                try
                {
                    localType = Ctx.Module.LookupMember(token) as ITypeDescriptor;
                }
                catch
                {
                    // Some protectors encode runtime-local descriptors that are not real metadata tokens.
                }

                method.MethodBody.Locals.Add(localType ?? Ctx.Module.CorLibTypeFactory.Object);
            }
        }

        public void ReadExceptionHandlers(VMMethod method, int exceptionHandlers)
        {
            for (var i = 0; i < exceptionHandlers; i++)
            {
                var EH = new VMExceptionHandler().Read(Ctx.Module, Ctx.Parser);
                method.MethodBody.ExceptionHandlers.Add(EH);
            }
        }

        public void ReadAllInstructions(VMMethod method, int instructions)
        {
            for (var i = 0; i < instructions; i++)
            {
                var b = Ctx.Parser.Reader.ReadByte();
                if (b < 0 || b >= Ctx.Parser.Operands.Length)
                    throw new DevirtualizationException($"Disassembling exception: invalid VM opcode byte {b}.");

                var instr = new VMInstruction(VMOpCode.Nop, null, i, b);
                instr.OpCode = Ctx.PatternMatcher.GetOpCodeValue(b);

                instr.Operand = ReadOperand(Ctx.Parser.Operands[b]);
                method.MethodBody.Instructions.Add(instr);
            }
        }

        private object ReadOperand(byte operandType)
        {
            return operandType switch
            {
                1 => Ctx.Parser.ReadEncryptedByte(),
                2 => Ctx.Parser.Reader.ReadInt64(),
                3 => Ctx.Parser.Reader.ReadSingle(),
                4 => Ctx.Parser.Reader.ReadDouble(),
                5 => ((Func<object>) (() =>
                {
                    var count = Ctx.Parser.ReadEncryptedByte();
                    var array = new int[count];
                    for (var i = 0; i < count; i++) array[i] = Ctx.Parser.ReadEncryptedByte();
                    return array;
                }))(),
                _ => null
            };
        }
    }
}
