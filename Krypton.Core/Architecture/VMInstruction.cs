namespace Krypton.Core.Architecture
{
    public class VMInstruction
    {
        public VMInstruction() : this(VMOpCode.Nop, null, 0, 0)
        {
        }

        public VMInstruction(VMOpCode opCode) : this(opCode, null, 0, 0)
        {
        }

        public VMInstruction(VMOpCode opcode, object operand) : this(opcode, operand, 0, 0)
        {
        }

        public VMInstruction(VMOpCode opcode, object operand, int offset) : this(opcode, operand, offset, 0)
        {
        }

        public VMInstruction(VMOpCode opcode, object operand, int offset, int vmByte)
        {
            OpCode = opcode;
            Operand = operand;
            Offset = offset;
            VmByte = vmByte;
        }

        public VMOpCode OpCode { get; set; }
        public object Operand { get; set; }
        public int Offset { get; set; }
        public int VmByte { get; set; }

        public override string ToString()
        {
            if (Operand != null) return $"[ {Offset} ] - [ vm:{VmByte} ] - [ {OpCode} ] - [ {Operand} ]";
            return $"[ {Offset} ] - [ vm:{VmByte} ] - [ {OpCode} ]";
        }
    }
}
