using Krypton.Core;

namespace Krypton.Pipeline.Stages
{
    public class MethodReplacing : IStage
    {
        public string Name => nameof(MethodReplacing);

        public void Run(DevirtualizationCtx Ctx)
        {
            var replaced = 0;
            foreach (var method in Ctx.VirtualizedMethods)
            {
                if (method.Parent == null || method.RecompiledBody == null)
                    continue;

                method.Parent.CilMethodBody = method.RecompiledBody;
                Ctx.Options.Logger.Info($"Replaced method body: {method.Parent.FullName}");
                replaced++;
            }

            Ctx.Options.Logger.Info($"Method bodies replaced: {replaced}");
        }
    }
}
