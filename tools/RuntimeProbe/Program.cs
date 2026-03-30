using System.Reflection;
using System.Runtime.CompilerServices;
using System.Runtime.Loader;

if (args.Length < 1)
{
    Console.WriteLine("usage: RuntimeProbe <assembly-path> [--call-policy] [--logical-type <full-name>] [--auth-type <full-name>] [--policy-type <full-name>]");
    return;
}

var assemblyPath = Path.GetFullPath(args[0]);
var callPolicy = args.Any(a => string.Equals(a, "--call-policy", StringComparison.OrdinalIgnoreCase));
var logicalTypeOverride = GetOption(args, "--logical-type");
var authTypeOverride = GetOption(args, "--auth-type");
var policyTypeOverride = GetOption(args, "--policy-type");
if (!File.Exists(assemblyPath))
{
    Console.WriteLine($"file not found: {assemblyPath}");
    return;
}

Console.WriteLine($"assembly: {assemblyPath}");
var assembly = AssemblyLoadContext.Default.LoadFromAssemblyPath(assemblyPath);
var allTypes = GetAllTypesSafe(assembly);

var logicalAnnotationType = ResolveType(
    assembly,
    allTypes,
    logicalTypeOverride,
    t => t.GetField("InvokeAuditor", BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Static) != null);
var authStateType = ResolveType(
    assembly,
    allTypes,
    authTypeOverride,
    t => t.GetMethod(
             "DefineRandomSharer",
             BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Static,
             binder: null,
             types: new[] { typeof(RuntimeTypeHandle) },
             modifiers: null) != null);
var policyTransmitterType = ResolveType(
    assembly,
    allTypes,
    policyTypeOverride,
    t => t.GetMethod(
             "EnforceIdentifiablePolicy",
             BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Static,
             binder: null,
             types: Type.EmptyTypes,
             modifiers: null) != null);
var annotationTracerType = allTypes.FirstOrDefault(
    t => t.GetField("MarkScalableConnection", BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Static) != null);
var dividedAnnotationType = allTypes.FirstOrDefault(
    t => t.GetField("MarkGenericNotifier", BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Static) != null);

if (logicalAnnotationType == null || authStateType == null)
{
    Console.WriteLine("required runtime types not found.");
    Console.WriteLine($"logical type: {logicalAnnotationType?.FullName ?? "<missing>"}");
    Console.WriteLine($"auth type: {authStateType?.FullName ?? "<missing>"}");
    Console.WriteLine("Use --logical-type/--auth-type for manual overrides.");
    return;
}

Console.WriteLine($"logical type: {logicalAnnotationType.FullName}");
Console.WriteLine($"auth type: {authStateType.FullName}");
if (policyTransmitterType != null)
    Console.WriteLine($"policy type: {policyTransmitterType.FullName}");

var invokeAuditorField = logicalAnnotationType.GetField(
    "InvokeAuditor",
    BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Static);
var markScalableConnectionField = annotationTracerType?.GetField(
    "MarkScalableConnection",
    BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Static);
var markGenericNotifierField = dividedAnnotationType?.GetField(
    "MarkGenericNotifier",
    BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Static);

DumpState("initial");

foreach (var module in assembly.Modules)
{
    try
    {
        RuntimeHelpers.RunModuleConstructor(module.ModuleHandle);
        Console.WriteLine($"module ctor ok: {module.Name}");
    }
    catch (Exception ex)
    {
        Console.WriteLine($"module ctor failed: {module.Name} -> {ex.GetType().Name}: {ex.Message}");
    }
}

DumpState("after module ctors");

try
{
    RuntimeHelpers.RunClassConstructor(logicalAnnotationType.TypeHandle);
    Console.WriteLine("LogicalAnnotation .cctor ok");
}
catch (Exception ex)
{
    Console.WriteLine($"LogicalAnnotation .cctor failed: {ex.GetType().Name}: {ex.Message}");
}

DumpState("after LogicalAnnotation .cctor");

var defineRandomSharer = authStateType.GetMethod(
    "DefineRandomSharer",
    BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Static,
    binder: null,
    types: new[] { typeof(RuntimeTypeHandle) },
    modifiers: null);

if (defineRandomSharer != null)
{
    try
    {
        defineRandomSharer.Invoke(null, new object[] { logicalAnnotationType.TypeHandle });
        Console.WriteLine("DefineRandomSharer(logical) invoke ok");
    }
    catch (TargetInvocationException tie)
    {
        Console.WriteLine($"DefineRandomSharer(logical) failed: {tie.InnerException?.GetType().Name}: {tie.InnerException?.Message}");
    }
    catch (Exception ex)
    {
        Console.WriteLine($"DefineRandomSharer(logical) failed: {ex.GetType().Name}: {ex.Message}");
    }
}

DumpState("after DefineRandomSharer(logical)");

if (callPolicy && policyTransmitterType != null)
{
    var enforceIdentifiablePolicy = policyTransmitterType.GetMethod(
        "EnforceIdentifiablePolicy",
        BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Static);
    if (enforceIdentifiablePolicy != null)
    {
        try
        {
            enforceIdentifiablePolicy.Invoke(null, null);
            Console.WriteLine("PolicyTransmitter.EnforceIdentifiablePolicy ok");
        }
        catch (TargetInvocationException tie)
        {
            Console.WriteLine("PolicyTransmitter.EnforceIdentifiablePolicy failed:");
            Console.WriteLine(tie.InnerException?.ToString());
        }
        catch (Exception ex)
        {
            Console.WriteLine($"PolicyTransmitter.EnforceIdentifiablePolicy failed: {ex}");
        }
    }
}

DumpState("final");
return;

static string? GetOption(string[] argv, string name)
{
    for (var i = 0; i < argv.Length - 1; i++)
    {
        if (string.Equals(argv[i], name, StringComparison.OrdinalIgnoreCase))
            return argv[i + 1];
    }

    return null;
}

static Type? ResolveType(Assembly assembly, IReadOnlyList<Type> allTypes, string? explicitName, Func<Type, bool> fallbackMatch)
{
    if (!string.IsNullOrWhiteSpace(explicitName))
        return assembly.GetType(explicitName, throwOnError: false, ignoreCase: false);

    return allTypes.FirstOrDefault(fallbackMatch);
}

static IReadOnlyList<Type> GetAllTypesSafe(Assembly assembly)
{
    try
    {
        return assembly.GetTypes();
    }
    catch (ReflectionTypeLoadException ex)
    {
        return ex.Types.Where(t => t != null).Cast<Type>().ToArray();
    }
}

void DumpState(string label)
{
    Console.WriteLine($"--- {label} ---");
    Console.WriteLine($"InvokeAuditor: {DescribeField(invokeAuditorField)}");
    Console.WriteLine($"MarkScalableConnection: {DescribeField(markScalableConnectionField)}");
    Console.WriteLine($"MarkGenericNotifier: {DescribeField(markGenericNotifierField)}");
}

string DescribeField(FieldInfo? field)
{
    if (field == null)
        return "<field not found>";

    object? value;
    try
    {
        value = field.GetValue(null);
    }
    catch (Exception ex)
    {
        return $"<error:{ex.GetType().Name}>";
    }

    if (value == null)
        return "null";

    return $"{value.GetType().FullName}";
}
