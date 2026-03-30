param(
    [Parameter(Mandatory = $true)]
    [string]$AssemblyPath,
    [switch]$CallPolicy,
    [switch]$DumpStatics,
    [switch]$DumpPolicyMap
)

$ErrorActionPreference = "Stop"

function Describe-Field([System.Reflection.FieldInfo]$Field)
{
    if ($null -eq $Field)
    {
        return "<field not found>"
    }

    try
    {
        $value = $Field.GetValue($null)
    }
    catch
    {
        return "<error:$($_.Exception.GetType().Name)>"
    }

    if ($null -eq $value)
    {
        return "null"
    }

    return $value.GetType().FullName
}

function Dump-State(
    [string]$Label,
    [System.Reflection.FieldInfo]$InvokeAuditorField,
    [System.Reflection.FieldInfo]$MarkScalableConnectionField,
    [System.Reflection.FieldInfo]$MarkGenericNotifierField)
{
    Write-Output "--- $Label ---"
    Write-Output ("InvokeAuditor: " + (Describe-Field $InvokeAuditorField))
    Write-Output ("MarkScalableConnection: " + (Describe-Field $MarkScalableConnectionField))
    Write-Output ("MarkGenericNotifier: " + (Describe-Field $MarkGenericNotifierField))
}

function Summarize-Value($Value)
{
    if ($null -eq $Value)
    {
        return "null"
    }

    if ($Value -is [string])
    {
        return "string:" + $Value
    }

    if ($Value -is [System.Array])
    {
        return "array(len=" + $Value.Length + ")"
    }

    if ($Value -is [System.Collections.IDictionary])
    {
        return "dict(count=" + $Value.Count + ")"
    }

    if ($Value -is [System.Collections.ICollection])
    {
        return "collection(count=" + $Value.Count + ")"
    }

    return $Value.GetType().FullName
}

function Dump-StaticFields([Type]$Type)
{
    if ($null -eq $Type)
    {
        return
    }

    Write-Output ("=== static fields: " + $Type.FullName + " ===")
    $bindingAll = [System.Reflection.BindingFlags]::Public `
        -bor [System.Reflection.BindingFlags]::NonPublic `
        -bor [System.Reflection.BindingFlags]::Static

    foreach ($field in ($Type.GetFields($bindingAll) | Sort-Object Name))
    {
        try
        {
            $value = $field.GetValue($null)
            Write-Output ($field.Name + " | " + $field.FieldType.FullName + " | " + (Summarize-Value $value))
        }
        catch
        {
            Write-Output ($field.Name + " | " + $field.FieldType.FullName + " | <error:" + $_.Exception.GetType().Name + ">")
        }
    }
}

$fullPath = (Resolve-Path $AssemblyPath).Path
Write-Output ("assembly: " + $fullPath)
$assembly = [System.Reflection.Assembly]::LoadFrom($fullPath)

$flags = [System.Reflection.BindingFlags]::Public `
    -bor [System.Reflection.BindingFlags]::NonPublic `
    -bor [System.Reflection.BindingFlags]::Static

$logicalType = $assembly.GetType("LogicalAnnotation")
$authType = $assembly.GetType("WindowsFormsApplication37.Internal.AuthenticatorState")
$policyType = $assembly.GetType("WindowsFormsApplication37.Internal.PolicyTransmitter")
$annotationTracerType = $assembly.GetType("AnnotationTracer")
$dividedAnnotationType = $assembly.GetType("DividedAnnotation")

if ($null -eq $logicalType -or $null -eq $authType)
{
    throw "required types not found"
}

$invokeAuditorField = $logicalType.GetField("InvokeAuditor", $flags)
$markScalableConnectionField = $null
if ($null -ne $annotationTracerType)
{
    $markScalableConnectionField = $annotationTracerType.GetField("MarkScalableConnection", $flags)
}

$markGenericNotifierField = $null
if ($null -ne $dividedAnnotationType)
{
    $markGenericNotifierField = $dividedAnnotationType.GetField("MarkGenericNotifier", $flags)
}

Dump-State -Label "initial" `
    -InvokeAuditorField $invokeAuditorField `
    -MarkScalableConnectionField $markScalableConnectionField `
    -MarkGenericNotifierField $markGenericNotifierField

foreach ($module in $assembly.GetModules())
{
    try
    {
        [System.Runtime.CompilerServices.RuntimeHelpers]::RunModuleConstructor($module.ModuleHandle)
        Write-Output ("module ctor ok: " + $module.Name)
    }
    catch
    {
        Write-Output ("module ctor failed: " + $module.Name + " -> " + $_.Exception.GetType().Name + ": " + $_.Exception.Message)
    }
}

Dump-State -Label "after module ctors" `
    -InvokeAuditorField $invokeAuditorField `
    -MarkScalableConnectionField $markScalableConnectionField `
    -MarkGenericNotifierField $markGenericNotifierField

try
{
    [System.Runtime.CompilerServices.RuntimeHelpers]::RunClassConstructor($logicalType.TypeHandle)
    Write-Output "LogicalAnnotation .cctor ok"
}
catch
{
    Write-Output ("LogicalAnnotation .cctor failed: " + $_.Exception.GetType().Name + ": " + $_.Exception.Message)
}

Dump-State -Label "after LogicalAnnotation .cctor" `
    -InvokeAuditorField $invokeAuditorField `
    -MarkScalableConnectionField $markScalableConnectionField `
    -MarkGenericNotifierField $markGenericNotifierField

$bindingAll = [System.Reflection.BindingFlags]::Public `
    -bor [System.Reflection.BindingFlags]::NonPublic `
    -bor [System.Reflection.BindingFlags]::Static

$defineRandomSharer = $authType.GetMethod(
    "DefineRandomSharer",
    $bindingAll,
    $null,
    [Type[]]@([System.RuntimeTypeHandle]),
    $null)

if ($null -ne $defineRandomSharer)
{
    try
    {
        $null = $defineRandomSharer.Invoke($null, @($logicalType.TypeHandle))
        Write-Output "DefineRandomSharer(logical) invoke ok"
    }
    catch
    {
        $inner = $_.Exception.InnerException
        if ($null -ne $inner)
        {
            Write-Output ("DefineRandomSharer(logical) failed: " + $inner.GetType().Name + ": " + $inner.Message)
        }
        else
        {
            Write-Output ("DefineRandomSharer(logical) failed: " + $_.Exception.GetType().Name + ": " + $_.Exception.Message)
        }
    }
}

Dump-State -Label "after DefineRandomSharer(logical)" `
    -InvokeAuditorField $invokeAuditorField `
    -MarkScalableConnectionField $markScalableConnectionField `
    -MarkGenericNotifierField $markGenericNotifierField

if ($CallPolicy -and $null -ne $policyType)
{
    $enforce = $policyType.GetMethod("EnforceIdentifiablePolicy", $bindingAll)
    if ($null -ne $enforce)
    {
        try
        {
            $null = $enforce.Invoke($null, $null)
            Write-Output "PolicyTransmitter.EnforceIdentifiablePolicy ok"
        }
        catch
        {
            $inner = $_.Exception.InnerException
            if ($null -ne $inner)
            {
                Write-Output "PolicyTransmitter.EnforceIdentifiablePolicy failed:"
                Write-Output $inner.ToString()
            }
            else
            {
                Write-Output ("PolicyTransmitter.EnforceIdentifiablePolicy failed: " + $_.Exception.ToString())
            }
        }
    }
}

Dump-State -Label "final" `
    -InvokeAuditorField $invokeAuditorField `
    -MarkScalableConnectionField $markScalableConnectionField `
    -MarkGenericNotifierField $markGenericNotifierField

if ($DumpStatics)
{
    Dump-StaticFields $logicalType
    Dump-StaticFields $annotationTracerType
    Dump-StaticFields $dividedAnnotationType
    Dump-StaticFields $authType
}

if ($DumpPolicyMap)
{
    $mapField = $authType.GetField("policyCreatorDic", $flags)
    if ($null -ne $mapField)
    {
        $map = $mapField.GetValue($null)
        if ($null -ne $map)
        {
            Write-Output "=== policyCreatorDic map ==="
            foreach ($entry in $map.GetEnumerator() | Sort-Object Key)
            {
                Write-Output ($entry.Key.ToString() + "=" + $entry.Value.ToString())
            }
        }
    }
}
