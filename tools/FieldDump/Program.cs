using System;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Runtime.CompilerServices;

if (args.Length < 1)
{
    Console.WriteLine("usage: FieldDump <assembly-path>");
    return;
}

var assemblyPath = Path.GetFullPath(args[0]);
if (!File.Exists(assemblyPath))
{
    Console.WriteLine($"file not found: {assemblyPath}");
    return;
}

var assembly = Assembly.LoadFrom(assemblyPath);
foreach (var module in assembly.Modules)
{
    try
    {
        RuntimeHelpers.RunModuleConstructor(module.ModuleHandle);
    }
    catch (Exception ex)
    {
        Console.WriteLine($"[warn] module ctor for {module.Name} failed: {ex.GetType().Name}: {ex.Message}");
    }
}

var flagsStatic = BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Static;
var flagsInstance = BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Instance;

var candidateTypes = assembly.GetTypes()
    .Where(t =>
        (t.FullName?.Contains("{", StringComparison.Ordinal) ?? false) ||
        string.Equals(t.Name, "<Module>", StringComparison.Ordinal))
    .ToList();

if (candidateTypes.Count == 0)
{
    Console.WriteLine("no candidate types found");
    return;
}

foreach (var type in candidateTypes.OrderBy(t => t.FullName, StringComparer.Ordinal))
{
    var staticFields = type.GetFields(flagsStatic);
    var instanceFields = type.GetFields(flagsInstance);

    var staticIntFields = staticFields
        .Where(f => f.FieldType == typeof(int))
        .OrderBy(f => f.MetadataToken)
        .ToList();

    var instanceIntFields = instanceFields
        .Where(f => f.FieldType == typeof(int))
        .OrderBy(f => f.MetadataToken)
        .ToList();

    var selfField = staticFields.FirstOrDefault(f => f.FieldType == type);
    object? instance = null;
    if (selfField != null)
    {
        try
        {
            instance = selfField.GetValue(null);
        }
        catch
        {
            instance = null;
        }
    }

    if (staticIntFields.Count == 0 && (instance == null || instanceIntFields.Count == 0))
        continue;

    Console.WriteLine($"TYPE {type.FullName}");
    if (selfField != null)
        Console.WriteLine($"SELF {selfField.Name}={(instance == null ? "null" : "non-null")}");

    foreach (var field in staticIntFields)
    {
        string valueText;
        try
        {
            valueText = Convert.ToString(field.GetValue(null)) ?? "<null>";
        }
        catch (Exception ex)
        {
            valueText = $"<error:{ex.GetType().Name}>";
        }

        Console.WriteLine($"S {field.MetadataToken:X8} {field.Name}={valueText}");
    }

    if (instance != null)
    {
        foreach (var field in instanceIntFields)
        {
            string valueText;
            try
            {
                valueText = Convert.ToString(field.GetValue(instance)) ?? "<null>";
            }
            catch (Exception ex)
            {
                valueText = $"<error:{ex.GetType().Name}>";
            }

            Console.WriteLine($"I {field.MetadataToken:X8} {field.Name}={valueText}");
        }
    }

    Console.WriteLine();
}
