namespace Krypton.Core.Architecture
{
    public enum VMOpCode
    {
        Nop,

        Ldstr,

        Call,
        Callvirt,

        Br,
        BrTrue,
        BrLessThan,
        BrFalse,

        Ldloc,
        Stloc,
        Ldfld,
        Ldsfld,
        Stsfld,
        Stfld,

        Pop,
        Dup,

        Ldc_I4,
        Ldelem_Ref,
        Ldelem_U1,
        Stelem_Ref,
        Stelem_I1,
        Add,
        Xor,
        Shl,
        Shr,
        Neg,
        Ldnull,
        Switch,

        Ldarg,
        Ldlen,
        Ldelema,
        Ldobj,
        Stobj,
        Conv_I4,
        Conv_I8,
        Conv_U1,
        Not,
        Sub,
        Newarr,
        Newobj,
        Ret,
        Leave
    }
}
