using System;
using System.Linq;
using AsmResolver.DotNet;

if (args.Length < 2)
{
    Console.WriteLine("usage: MethodFullDump <assembly> <method-name-substring|method-token|call:<callee-substring>>");
    Console.WriteLine("example token formats: 0x06000004, 06000004, 4 (RID)");
    return;
}

var module = ModuleDefinition.FromFile(args[0]);
var query = args[1];
var allMethods = module.GetAllTypes()
    .SelectMany(t => t.Methods)
    .Where(m => m.IsIL && m.CilMethodBody != null)
    .ToList();

var methods = new System.Collections.Generic.List<MethodDefinition>();
if (query.StartsWith("call:", StringComparison.OrdinalIgnoreCase))
{
    var calleeQuery = query.Substring("call:".Length).Trim();
    methods.AddRange(allMethods.Where(m => ContainsCallee(m, calleeQuery)));
}
else if (query.StartsWith("calltoken:", StringComparison.OrdinalIgnoreCase))
{
    var tokenText = query.Substring("calltoken:".Length).Trim();
    if (TryParseMethodToken(tokenText, out var calleeToken))
        methods.AddRange(allMethods.Where(m => ContainsCalleeToken(m, calleeToken)));
}
else if (TryParseMethodToken(query, out var methodToken))
{
    methods.AddRange(allMethods.Where(m => GetMethodToken(m) == methodToken));
}
else
{
    methods.AddRange(allMethods.Where(m =>
        m.FullName.IndexOf(query, StringComparison.OrdinalIgnoreCase) >= 0));
}

if (methods.Count == 0)
{
    Console.WriteLine("no method match");
    return;
}

foreach (var method in methods)
{
    var body = method.CilMethodBody!;
    Console.WriteLine($"{method.FullName} [token=0x{GetMethodToken(method):X8}]");
    Console.WriteLine($"Instructions: {body.Instructions.Count} | Locals: {body.LocalVariables.Count}");
    for (var i = 0; i < body.Instructions.Count; i++)
    {
        var instruction = body.Instructions[i];
        var operand = instruction.Operand == null
            ? string.Empty
            : " " + instruction.Operand;

        if (instruction.Operand is IMethodDescriptor methodDescriptor)
        {
            try
            {
                var resolved = methodDescriptor.Resolve();
                if (resolved != null)
                    operand += $" [resolved=0x{GetMethodToken(resolved):X8}]";
            }
            catch (InvalidOperationException)
            {
                // Some malformed/protector-generated member refs are not true method refs.
            }
        }

        Console.WriteLine($"[{i}] {instruction.OpCode.Code}{operand}");
    }

    if (body.ExceptionHandlers.Count > 0)
    {
        Console.WriteLine("EH:");
        foreach (var eh in body.ExceptionHandlers)
            Console.WriteLine(eh);
    }

    Console.WriteLine();
}

static bool ContainsCallee(MethodDefinition method, string calleeQuery)
{
    if (string.IsNullOrWhiteSpace(calleeQuery) || method.CilMethodBody == null)
        return false;

    foreach (var instruction in method.CilMethodBody.Instructions)
    {
        if (instruction.Operand == null)
            continue;

        var text = instruction.Operand.ToString();
        if (text != null && text.IndexOf(calleeQuery, StringComparison.OrdinalIgnoreCase) >= 0)
            return true;
    }

    return false;
}

static bool ContainsCalleeToken(MethodDefinition method, uint calleeToken)
{
    if (calleeToken == 0 || method.CilMethodBody == null)
        return false;

    foreach (var instruction in method.CilMethodBody.Instructions)
    {
        if (instruction.Operand is not IMethodDescriptor descriptor)
            continue;

        try
        {
            var resolved = descriptor.Resolve();
            if (resolved != null && GetMethodToken(resolved) == calleeToken)
                return true;
        }
        catch (InvalidOperationException)
        {
            // Non-method member-ref shape.
        }
    }

    return false;
}

static bool TryParseMethodToken(string query, out uint token)
{
    token = 0;
    if (string.IsNullOrWhiteSpace(query))
        return false;

    var text = query.Trim();
    if (text.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
        text = text.Substring(2);

    if (!uint.TryParse(
            text,
            System.Globalization.NumberStyles.HexNumber,
            System.Globalization.CultureInfo.InvariantCulture,
            out var parsedHex))
    {
        return false;
    }

    if ((parsedHex & 0xFF000000u) == 0x06000000u)
    {
        token = parsedHex;
        return true;
    }

    if (parsedHex != 0 && parsedHex <= 0x00FFFFFFu)
    {
        token = 0x06000000u | parsedHex;
        return true;
    }

    return false;
}

static uint GetMethodToken(MethodDefinition method)
{
    var raw = method.MetadataToken.ToUInt32();
    if (raw != 0)
        return raw;

    return 0x06000000u | method.MetadataToken.Rid;
}
