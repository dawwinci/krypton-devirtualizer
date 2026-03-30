using System.IO;
using System.Text;

namespace Krypton.Core.Parser
{
    public class ResourceParser
    {
        public int[] MethodKeys { get; set; }
        public byte[] Operands { get; set; }
        public string[] Strings { get; set; }
        public BinaryReader Reader { get; set; }

        public ResourceParser Parse(DevirtualizationCtx Ctx)
        {
            foreach (var resource in Ctx.Module.Resources)
            {
                byte[] data;
                try
                {
                    data = resource.GetData();
                }
                catch
                {
                    continue;
                }

                if (!TryParseLayout(data, out var operands, out var strings, out var methodKeys))
                    continue;

                Reader = new BinaryReader(new MemoryStream(data));
                Operands = operands;
                Strings = strings;
                MethodKeys = methodKeys;
                Ctx.Options.Logger.Success(
                    $"Located Resource With Name {resource.Name} And Byte Data Length {data.Length}");
                return this;
            }

            throw new DevirtualizationException("Could not locate VM resource payload.");
        }

        private bool TryParseLayout(
            byte[] data,
            out byte[] operands,
            out string[] strings,
            out int[] methodKeys)
        {
            operands = null;
            strings = null;
            methodKeys = null;

            if (data == null || data.Length == 0)
                return false;

            try
            {
                using var stream = new MemoryStream(data, false);
                using var reader = new BinaryReader(stream);

                var parsedOperands = new byte[255];
                var operandCount = ReadEncryptedByte(reader);
                if (operandCount < 0 || operandCount > 255)
                    return false;

                for (var i = 0; i < operandCount; i++)
                {
                    if (reader.BaseStream.Position + 2 > reader.BaseStream.Length)
                        return false;

                    var index = reader.ReadByte();
                    parsedOperands[index] = reader.ReadByte();
                }

                var stringCount = ReadEncryptedByte(reader);
                if (stringCount < 0 || stringCount > 0x4000)
                    return false;

                var parsedStrings = new string[stringCount];
                for (var i = 0; i < stringCount; i++)
                {
                    var size = ReadEncryptedByte(reader);
                    if (size < 0 || reader.BaseStream.Position + size > reader.BaseStream.Length)
                        return false;

                    parsedStrings[i] = Encoding.Unicode.GetString(reader.ReadBytes(size));
                }

                var methodCount = ReadEncryptedByte(reader);
                if (methodCount <= 0 || methodCount > 0x8000)
                    return false;

                var methodSizes = new int[methodCount];
                for (var i = 0; i < methodCount; i++)
                {
                    var size = ReadEncryptedByte(reader);
                    if (size <= 0)
                        return false;
                    methodSizes[i] = size;
                }

                var methodPosition = (int)reader.BaseStream.Position;
                var parsedMethodKeys = new int[methodCount];
                for (var i = 0; i < methodCount; i++)
                {
                    parsedMethodKeys[i] = methodPosition;
                    methodPosition += methodSizes[i];
                }

                if (methodPosition > data.Length)
                    return false;

                operands = parsedOperands;
                strings = parsedStrings;
                methodKeys = parsedMethodKeys;
                return true;
            }
            catch
            {
                return false;
            }
        }

        public int ReadEncryptedByte()
        {
            return ReadEncryptedByte(Reader);
        }

        private int ReadEncryptedByte(BinaryReader reader)
        {
            var flag = false;
            var num = 0U;
            var num2 = reader.ReadByte();
            num |= num2 & 63U;
            if ((num2 & 64U) != 0U) flag = true;
            if (num2 < 128U)
            {
                if (flag)
                    return ~(int)num;
                return (int)num;
            }

            var num3 = 0;
            for (;;)
            {
                var num4 = (uint)reader.ReadByte();
                num |= (num4 & 127U) << (7 * num3 + 6);
                if (num4 < 128U) break;
                num3++;
            }

            if (flag) return ~(int)num;
            return (int)num;
        }
    }
}
