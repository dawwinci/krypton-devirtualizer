using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Reflection.Metadata;
using System.Reflection.Metadata.Ecma335;
using System.Reflection.PortableExecutable;
using AsmResolver.DotNet;
using AsmResolver.DotNet.Code.Cil;
using AsmResolver.DotNet.Builder;
using AsmResolver.PE.DotNet.Cil;
using Krypton.Core;
using Krypton.Pipeline.Stages;

namespace Krypton.Pipeline
{
    public class Devirtualizer
    {
        public Devirtualizer(DevirtualizationCtx Ctx)
        {
            this.Ctx = Ctx;
            Stages = new List<IStage>
            {
                new ResourceParsing(),
                new OpcodeMapping(),
                new MethodDisassembling(),
                new MethodRecompiling(),
                new MethodReplacing()
            };
        }

        public DevirtualizationCtx Ctx { get; set; }
        public List<IStage> Stages { get; set; }

        public void Devirtualize()
        {
            foreach (var stage in Stages)
            {
                Ctx.Options.Logger.Info($"Executing {stage.Name} Stage...");
                stage.Run(Ctx);
                Ctx.Options.Logger.Success($"Executed {stage.Name} Stage!");
            }
        }

        public void Save()
        {
            if (Ctx.VirtualizedMethods == null || Ctx.VirtualizedMethods.Count == 0)
            {
                Ctx.Options.Logger.Warning("No virtualized methods were disassembled, report generation skipped.");
                return;
            }

            var reportPath = Path.Combine(
                Path.GetDirectoryName(Ctx.Options.OutPath)!,
                Path.GetFileNameWithoutExtension(Ctx.Options.OutPath) + "-report.txt");

            var sb = new StringBuilder();
            sb.AppendLine("Krypton Disassembly Report");
            sb.AppendLine("=========================");
            sb.AppendLine($"Input: {Ctx.Options.FilePath}");
            sb.AppendLine($"Methods: {Ctx.VirtualizedMethods.Count}");
            sb.AppendLine();

            foreach (var method in Ctx.VirtualizedMethods)
            {
                var resolvedName = method.Parent?.FullName ?? "<unresolved method>";
                var total = method.MethodBody.Instructions.Count;
                var mapped = method.MethodBody.Instructions.Count(i => i.OpCode != Core.Architecture.VMOpCode.Nop);
                var unknownGroups = method.MethodBody.Instructions
                    .Where(i => i.OpCode == Core.Architecture.VMOpCode.Nop)
                    .GroupBy(i => i.VmByte)
                    .OrderByDescending(g => g.Count())
                    .ThenBy(g => g.Key)
                    .Select(g => $"0x{g.Key:X2}:{g.Count()}");

                sb.AppendLine($"MethodKey: {method.MethodKey}");
                sb.AppendLine($"Parent: {resolvedName}");
                sb.AppendLine($"Locals: {method.MethodBody.Locals.Count} | EH: {method.MethodBody.ExceptionHandlers.Count}");
                if (method.MethodBody.ExceptionHandlers.Count > 0)
                {
                    for (var i = 0; i < method.MethodBody.ExceptionHandlers.Count; i++)
                    {
                        var eh = method.MethodBody.ExceptionHandlers[i];
                        var extra = eh.EHType switch
                        {
                            Core.Architecture.VMExceptionHandlerType.Catch => $" catch:{eh.CatchType}",
                            Core.Architecture.VMExceptionHandlerType.Filter => $" filter:{eh.Filter}",
                            _ => string.Empty
                        };
                        sb.AppendLine(
                            $"  EH[{i}] try:[{eh.TryStart},{eh.TryEnd}] handler:[{eh.HandlerStart},{eh.HandlerEnd}] type:{eh.EHType}{extra}");
                    }
                }
                sb.AppendLine($"Instructions: {total} | Mapped: {mapped} | Unknown: {total - mapped}");
                sb.AppendLine($"Unknown VM bytes: {(total == mapped ? "<none>" : string.Join(", ", unknownGroups))}");
                sb.AppendLine("Used VM bytes (byte -> opcode, operand-type):");
                foreach (var vmByte in method.MethodBody.Instructions.Select(i => i.VmByte).Distinct().OrderBy(i => i))
                {
                    var opcode = Ctx.PatternMatcher.GetOpCodeValue(vmByte);
                    var operandType = Ctx.Parser.Operands[vmByte];
                    sb.AppendLine($"  0x{vmByte:X2} -> {opcode}, operand:{operandType}");
                }
                sb.AppendLine("Unknown handler snippets:");
                foreach (var vmByte in method.MethodBody.Instructions
                             .Where(i => i.OpCode == Core.Architecture.VMOpCode.Nop)
                             .Select(i => i.VmByte)
                             .Distinct()
                             .OrderBy(i => i))
                {
                    sb.AppendLine($"  vm 0x{vmByte:X2}:");
                    foreach (var line in GetHandlerSnippet(vmByte))
                        sb.AppendLine($"    {line}");
                }
                sb.AppendLine("Instructions:");
                foreach (var instruction in method.MethodBody.Instructions)
                    sb.AppendLine($"  {FormatInstruction(instruction)}");
                sb.AppendLine();
            }

            File.WriteAllText(reportPath, sb.ToString());
            Ctx.Options.Logger.Success($"Wrote report at {reportPath}");

            var methodsWithUnknown = Ctx.VirtualizedMethods
                .Where(q => q.MethodBody.Instructions.Any(i => i.OpCode == Core.Architecture.VMOpCode.Nop))
                .ToList();
            if (methodsWithUnknown.Count > 0)
            {
                Ctx.Options.Logger.Warning(
                    $"Detected unresolved VM opcodes in {methodsWithUnknown.Count} method(s). Writing partial output with only fully recompiled methods replaced.");
            }

            var hasRecompiledBodies = Ctx.VirtualizedMethods.Any(q => q.RecompiledBody != null);
            if (!hasRecompiledBodies)
            {
                Ctx.Options.Logger.Warning("No method was fully recompiled and replaced. Skipping assembly write.");
                if (File.Exists(Ctx.Options.OutPath))
                    Ctx.Options.Logger.Warning(
                        $"Existing file at {Ctx.Options.OutPath} is from an older run and does not reflect current report.");
                return;
            }

            if (TryWriteInPlacePatchedAssembly())
            {
                Ctx.Options.Logger.Success($"Wrote File At {Ctx.Options.OutPath}");
                return;
            }

            Ctx.Options.Logger.Warning(
                "In-place method patch failed. Skipping full PE rebuild to avoid producing a broken PE layout. " +
                "Use the unpacked/working base binary (e.g. awesome_msil_Out.exe) as input.");
            if (File.Exists(Ctx.Options.OutPath))
            {
                Ctx.Options.Logger.Warning(
                    $"File at {Ctx.Options.OutPath} was not freshly patched in this run and may be stale/unchanged.");
            }
        }

        private bool TryWriteInPlacePatchedAssembly()
        {
            var methodsToPatch = Ctx.VirtualizedMethods
                .Where(q => q.Parent != null && q.RecompiledBody != null)
                .ToList();
            if (methodsToPatch.Count == 0)
                return false;

            var tempPath = Path.Combine(
                Path.GetDirectoryName(Ctx.Options.OutPath)!,
                Path.GetFileNameWithoutExtension(Ctx.Options.OutPath) + ".tmp-rewrite" + Path.GetExtension(Ctx.Options.OutPath));

            try
            {
                // Keep final output layout identical to the original by patching directly into a copied file.
                File.Copy(Ctx.Options.FilePath, Ctx.Options.OutPath, true);

                var enableHashtableSanitize = GetFeatureToggle(
                    "KRYPTON_ENABLE_HASHTABLE_SANITIZE",
                    defaultEnabled: true,
                    disableVariableName: "KRYPTON_DISABLE_HASHTABLE_SANITIZE");
                if (enableHashtableSanitize)
                {
                    var patchedHashtableCtors = SanitizeHashtableCapacityConstructors(Ctx.Module);
                    if (patchedHashtableCtors > 0)
                    {
                        Ctx.Options.Logger.Warning(
                            $"Sanitized {patchedHashtableCtors} Hashtable(Int32) constructor call(s) to avoid invalid negative capacities.");
                    }
                }

                var enableWinFormsGuardBypass = GetFeatureToggle(
                    "KRYPTON_ENABLE_WINFORMS_GUARD_BYPASS",
                    defaultEnabled: true,
                    disableVariableName: "KRYPTON_DISABLE_WINFORMS_GUARD_BYPASS");
                if (enableWinFormsGuardBypass)
                {
                    var bypassedFormGuards = BypassWindowsFormsEntryGuards(Ctx.Module);
                    if (bypassedFormGuards > 0)
                    {
                        Ctx.Options.Logger.Warning(
                            $"Bypassed {bypassedFormGuards} Windows Forms anti-tamper entry guard(s).");
                    }
                }

                // Preserve definition table indices/tokens to avoid breaking protectors that do token-based runtime lookups.
                // Do not preserve all tables: some samples contain duplicate member refs that fail full token preservation.
                var metadataBuilderFlags =
                    MetadataBuilderFlags.PreserveTypeDefinitionIndices |
                    MetadataBuilderFlags.PreserveFieldDefinitionIndices |
                    MetadataBuilderFlags.PreserveMethodDefinitionIndices |
                    MetadataBuilderFlags.PreserveParameterDefinitionIndices |
                    MetadataBuilderFlags.PreserveEventDefinitionIndices |
                    MetadataBuilderFlags.PreservePropertyDefinitionIndices |
                    MetadataBuilderFlags.PreserveMemberReferenceIndices |
                    MetadataBuilderFlags.NoStringsStreamOptimization;

                // Build a temporary rewritten image only to extract the new method body bytes.
                var stripMalformedAttributes = string.Equals(
                    Environment.GetEnvironmentVariable("KRYPTON_STRIP_MALFORMED_ATTRIBUTES"),
                    "1",
                    StringComparison.Ordinal);
                if (stripMalformedAttributes)
                {
                    var removed = StripMalformedCustomAttributes(Ctx.Module);
                    if (removed > 0)
                        Ctx.Options.Logger.Warning($"Removed {removed} malformed custom attributes before temporary donor write.");
                }

                var disableStartupGuard = GetFeatureToggle(
                    "KRYPTON_DISABLE_STARTUP_GUARD",
                    defaultEnabled: false);
                if (disableStartupGuard)
                {
                    var disableAllBootstrapCctors = string.Equals(
                        Environment.GetEnvironmentVariable("KRYPTON_DISABLE_ALL_BOOTSTRAP_CCTORS"),
                        "1",
                        StringComparison.Ordinal);
                    var disabled = disableAllBootstrapCctors
                        ? DisableBootstrapTypeInitializers(Ctx.Module, Ctx.Module.GetAllTypes())
                        : DisableBootstrapTypeInitializers(Ctx.Module, GetBootstrapCandidateTypes(methodsToPatch));
                    if (disabled > 0)
                        Ctx.Options.Logger.Warning(
                            $"Neutralized {disabled} bootstrap-like static constructor(s) in temporary donor.");
                }

                var neutralizeSharedBootstrap = GetFeatureToggle(
                    "KRYPTON_NEUTRALIZE_SHARED_BOOTSTRAP",
                    defaultEnabled: true,
                    disableVariableName: "KRYPTON_DISABLE_SHARED_BOOTSTRAP_NEUTRALIZE");
                if (neutralizeSharedBootstrap)
                {
                    var neutralizedWorkers = NeutralizeSharedBootstrapMethods(Ctx.Module);
                    if (neutralizedWorkers > 0)
                    {
                        Ctx.Options.Logger.Warning(
                            $"Neutralized {neutralizedWorkers} shared bootstrap worker method(s) referenced by multiple static constructors.");
                    }
                }
                var repairedTypeRefs = RepairInvalidTypeReferences(Ctx.Module, Ctx.Options.FilePath);
                if (repairedTypeRefs > 0)
                {
                    Ctx.Options.Logger.Warning(
                        $"Repaired {repairedTypeRefs} invalid type reference scope(s) before donor write.");
                }
                NormalizeAssemblyIdentity(Ctx.Module);
                try
                {
                    Ctx.Module.Write(
                        tempPath,
                        new ManagedPEImageBuilder(new DotNetDirectoryFactory(metadataBuilderFlags)));
                }
                catch (Exception ex) when (!stripMalformedAttributes)
                {
                    Ctx.Options.Logger.Warning(
                        $"Temporary donor write failed without attribute stripping ({ex.Message}). Retrying with malformed-attribute cleanup.");
                    var removed = StripMalformedCustomAttributes(Ctx.Module);
                    if (removed > 0)
                        Ctx.Options.Logger.Warning($"Removed {removed} malformed custom attributes before retry donor write.");
                    try
                    {
                        Ctx.Module.Write(
                            tempPath,
                            new ManagedPEImageBuilder(new DotNetDirectoryFactory(metadataBuilderFlags)));
                    }
                    catch (Exception retryEx)
                    {
                        Ctx.Options.Logger.Warning(
                            $"Retry donor write after malformed-attribute cleanup failed ({retryEx.Message}). Retrying with full custom-attribute strip.");
                        var cleared = ClearAllCustomAttributes(Ctx.Module);
                        if (cleared > 0)
                            Ctx.Options.Logger.Warning($"Removed {cleared} custom attributes before final donor write retry.");
                        Ctx.Module.Write(
                            tempPath,
                            new ManagedPEImageBuilder(new DotNetDirectoryFactory(metadataBuilderFlags)));
                    }
                }

                var useRewriteOutput = !string.Equals(
                    Environment.GetEnvironmentVariable("KRYPTON_USE_INPLACE_PATCH"),
                    "1",
                    StringComparison.Ordinal);
                if (useRewriteOutput)
                {
                    File.Copy(tempPath, Ctx.Options.OutPath, true);
                    ClearInvalidStrongNameFlag(Ctx.Options.OutPath);
                    Ctx.Options.Logger.Info("Using rewritten assembly output (manual in-place patch disabled by default).");
                    return true;
                }

                var targetBytes = File.ReadAllBytes(Ctx.Options.OutPath);
                var donorBytes = File.ReadAllBytes(tempPath);

                var targetLayout = ReadPeLayout(targetBytes);
                var donorLayout = ReadPeLayout(donorBytes);

                var targetMethodRvas = GetMethodBodyRvas(Ctx.Options.OutPath);
                var donorMethodRvas = GetMethodBodyRvas(tempPath);
                var donorMethodTokensByFullName = GetMethodTokensByFullName(tempPath);
                var capacities = BuildMethodBodyCapacities(targetMethodRvas, targetLayout);

                var patched = 0;
                foreach (var vmMethod in methodsToPatch)
                {
                    var token = vmMethod.Parent!.MetadataToken.ToUInt32();
                    if (!targetMethodRvas.TryGetValue(token, out var targetRva))
                        throw new DevirtualizationException($"Could not resolve method token 0x{token:X8} for in-place patch.");

                    var methodFullName = vmMethod.Parent.FullName;
                    if (!donorMethodTokensByFullName.TryGetValue(methodFullName, out var donorToken))
                        donorToken = token;

                    if (!donorMethodRvas.TryGetValue(donorToken, out var donorRva))
                        throw new DevirtualizationException(
                            $"Could not resolve donor method RVA for {methodFullName} (token 0x{donorToken:X8}).");

                    if (donorToken != token)
                    {
                        Ctx.Options.Logger.Info(
                            $"Resolved donor token remap for {methodFullName}: 0x{token:X8} -> 0x{donorToken:X8}.");
                    }

                    if (targetRva == 0 || donorRva == 0)
                    {
                        throw new DevirtualizationException(
                            $"Method token 0x{token:X8} / donor token 0x{donorToken:X8} has no method body RVA.");
                    }

                    var targetOffset = RvaToFileOffset(targetLayout, targetRva);
                    var donorOffset = RvaToFileOffset(donorLayout, donorRva);
                    var oldBodySize = GetMethodBodySize(targetBytes, targetOffset);
                    var newBodySize = GetMethodBodySize(donorBytes, donorOffset);

                    if (!capacities.TryGetValue(token, out var capacity))
                        throw new DevirtualizationException($"Could not determine in-place capacity for method token 0x{token:X8}.");

                    if (newBodySize <= capacity)
                    {
                        Buffer.BlockCopy(donorBytes, donorOffset, targetBytes, targetOffset, newBodySize);
                        if (newBodySize < oldBodySize)
                            Array.Clear(targetBytes, targetOffset + newBodySize, oldBodySize - newBodySize);
                    }
                    else
                    {
                        var relocatedBody = new byte[newBodySize];
                        Buffer.BlockCopy(donorBytes, donorOffset, relocatedBody, 0, newBodySize);
                        var newRva = AppendMethodBodyToPreferredSection(
                            ref targetBytes,
                            targetLayout,
                            relocatedBody,
                            targetRva);
                        PatchMethodDefinitionRva(targetBytes, targetLayout, token, newRva);
                        targetMethodRvas[token] = newRva;
                        Ctx.Options.Logger.Warning(
                            $"Relocated method token 0x{token:X8} to RVA 0x{newRva:X8} because body size {newBodySize} exceeded original capacity {capacity}.");
                    }

                    patched++;
                }

                File.WriteAllBytes(Ctx.Options.OutPath, targetBytes);
                ClearInvalidStrongNameFlag(Ctx.Options.OutPath);
                Ctx.Options.Logger.Info($"Patched {patched} method body(s) in-place.");
                return patched > 0;
            }
            catch (Exception ex)
            {
                Ctx.Options.Logger.Warning($"In-place patch failed: {ex.Message}");
                return false;
            }
            finally
            {
                if (File.Exists(tempPath))
                {
                    try
                    {
                        File.Delete(tempPath);
                    }
                    catch
                    {
                        // Best effort cleanup.
                    }
                }
            }
        }

        private Dictionary<uint, int> BuildMethodBodyCapacities(
            Dictionary<uint, uint> methodRvas,
            PeLayout layout)
        {
            var methods = methodRvas
                .Where(kv => kv.Value > 0)
                .OrderBy(kv => kv.Value)
                .ToList();

            var result = new Dictionary<uint, int>();
            for (var i = 0; i < methods.Count; i++)
            {
                var methodToken = methods[i].Key;
                var methodRva = methods[i].Value;
                var section = GetSectionForRva(layout, methodRva);
                if (section == null)
                    continue;

                uint? nextRva = null;
                for (var j = i + 1; j < methods.Count; j++)
                {
                    if (methods[j].Value > methodRva)
                    {
                        nextRva = methods[j].Value;
                        break;
                    }
                }

                var sectionSpan = Math.Max(section.VirtualSize, section.RawSize);
                var sectionEndRva = section.VirtualAddress + sectionSpan;
                var capacity = (int) ((nextRva ?? sectionEndRva) - methodRva);
                if (capacity <= 0)
                    continue;

                result[methodToken] = capacity;
            }

            return result;
        }

        private Dictionary<uint, uint> GetMethodBodyRvas(string filePath)
        {
            using var stream = File.OpenRead(filePath);
            using var peReader = new PEReader(stream, PEStreamOptions.PrefetchMetadata);
            var metadata = peReader.GetMetadataReader();

            var result = new Dictionary<uint, uint>();
            foreach (var handle in metadata.MethodDefinitions)
            {
                var token = (uint) MetadataTokens.GetToken(handle);
                var row = metadata.GetMethodDefinition(handle);
                result[token] = unchecked((uint) row.RelativeVirtualAddress);
            }

            return result;
        }

        private Dictionary<string, uint> GetMethodTokensByFullName(string filePath)
        {
            var module = AsmResolver.DotNet.ModuleDefinition.FromFile(filePath);
            var result = new Dictionary<string, uint>(StringComparer.Ordinal);
            foreach (var type in module.GetAllTypes())
            {
                foreach (var method in type.Methods)
                {
                    var key = method.FullName;
                    if (!result.ContainsKey(key))
                        result[key] = method.MetadataToken.ToUInt32();
                }
            }

            return result;
        }

        private int RvaToFileOffset(PeLayout layout, uint rva)
        {
            var section = GetSectionForRva(layout, rva);
            if (section == null)
                throw new DevirtualizationException($"Could not map RVA 0x{rva:X8} to file offset.");

            return checked((int) (section.RawPointer + (rva - section.VirtualAddress)));
        }

        private PeSection GetSectionForRva(PeLayout layout, uint rva)
        {
            foreach (var section in layout.Sections)
            {
                var sectionSpan = Math.Max(section.VirtualSize, section.RawSize);
                var end = section.VirtualAddress + sectionSpan;
                if (rva >= section.VirtualAddress && rva < end)
                    return section;
            }

            return null;
        }

        private int GetMethodBodySize(byte[] image, int offset)
        {
            if (offset < 0 || offset >= image.Length)
                throw new DevirtualizationException($"Method body offset 0x{offset:X8} is outside image bounds.");

            var first = image[offset];
            var format = first & 0x3;
            switch (format)
            {
                case 0x2: // tiny
                    return 1 + (first >> 2);
                case 0x3: // fat
                {
                    var flags = BitConverter.ToUInt16(image, offset);
                    var headerDwords = (flags >> 12) & 0xF;
                    var headerSize = headerDwords * 4;
                    if (headerSize <= 0)
                        throw new DevirtualizationException("Invalid fat method header size.");

                    var codeSize = BitConverter.ToInt32(image, offset + 4);
                    var total = headerSize + codeSize;
                    if ((flags & 0x8) == 0)
                        return total;

                    var sectionOffset = offset + Align4(total);
                    var hasMoreSections = true;
                    while (hasMoreSections)
                    {
                        if (sectionOffset + 4 > image.Length)
                            throw new DevirtualizationException("Method data section exceeds image bounds.");

                        var kind = image[sectionOffset];
                        hasMoreSections = (kind & 0x80) != 0;
                        var fatSection = (kind & 0x40) != 0;

                        int dataSize;
                        if (fatSection)
                        {
                            dataSize = image[sectionOffset + 1]
                                       | (image[sectionOffset + 2] << 8)
                                       | (image[sectionOffset + 3] << 16);
                        }
                        else
                        {
                            dataSize = image[sectionOffset + 1];
                        }

                        if (dataSize <= 0)
                            throw new DevirtualizationException("Invalid method data section size.");

                        sectionOffset += Align4(dataSize);
                    }

                    return sectionOffset - offset;
                }
                default:
                    throw new DevirtualizationException($"Unsupported method body format 0x{format:X}.");
            }
        }

        private int Align4(int value) => (value + 3) & ~3;

        private uint Align(uint value, uint alignment)
        {
            if (alignment == 0)
                return value;
            var mask = alignment - 1;
            return (value + mask) & ~mask;
        }

        private uint AppendMethodBodyToPreferredSection(
            ref byte[] image,
            PeLayout layout,
            byte[] bodyBytes,
            uint preferredRva)
        {
            var section = GetSectionForRva(layout, preferredRva);
            var textSection = layout.Sections.FirstOrDefault(s =>
                s.Name.Equals(".text", StringComparison.OrdinalIgnoreCase) ||
                s.Name.StartsWith(".text", StringComparison.OrdinalIgnoreCase));
            if (textSection != null &&
                (section == null || !section.Name.StartsWith(".text", StringComparison.OrdinalIgnoreCase)))
            {
                if (section != null)
                {
                    Ctx.Options.Logger.Warning(
                        $"Relocation target section switched from '{section.Name}' to '{textSection.Name}' for dnSpy-friendly method body placement.");
                }

                section = textSection;
            }

            section ??= GetOrCreatePatchCodeSection(ref image, layout);
            if (section == null)
                throw new DevirtualizationException("Could not locate or create a patch code section.");

            // Keep RVA/file mapping consistent even when VirtualSize != RawSize.
            var sectionSpan = Math.Max(section.VirtualSize, section.RawSize);
            var bodyStart = Align(sectionSpan, 4);
            var newRva = section.VirtualAddress + bodyStart;
            var newRawOffset = section.RawPointer + bodyStart;

            var requiredVirtualSize = bodyStart + (uint) bodyBytes.Length;
            var requiredRawSize = Align(requiredVirtualSize, layout.FileAlignment);
            EnsureSectionRawCapacity(ref image, layout, section, requiredRawSize);

            var requiredLength = checked((int) (section.RawPointer + requiredRawSize));
            if (requiredLength > image.Length)
                Array.Resize(ref image, requiredLength);

            Buffer.BlockCopy(bodyBytes, 0, image, checked((int) newRawOffset), bodyBytes.Length);

            section.VirtualSize = Math.Max(section.VirtualSize, requiredVirtualSize);
            section.RawSize = Math.Max(section.RawSize, requiredRawSize);
            WriteUInt32(image, section.HeaderOffset + 8, section.VirtualSize);
            WriteUInt32(image, section.HeaderOffset + 16, section.RawSize);

            var sizeOfImage = layout.Sections
                .Select(s => s.VirtualAddress + Align(Math.Max(s.VirtualSize, s.RawSize), layout.SectionAlignment))
                .Max();
            WriteUInt32(image, layout.SizeOfImageOffset, sizeOfImage);

            return newRva;
        }

        private void EnsureSectionRawCapacity(
            ref byte[] image,
            PeLayout layout,
            PeSection section,
            uint requiredRawSize)
        {
            if (requiredRawSize <= section.RawSize)
                return;

            var growth = requiredRawSize - section.RawSize;
            if (growth == 0)
                return;

            var ordered = layout.Sections
                .OrderBy(s => s.RawPointer)
                .ToList();
            var sectionIndex = ordered.IndexOf(section);
            if (sectionIndex < 0)
                throw new DevirtualizationException("Target section is missing from PE layout.");

            var insertAt = section.RawPointer + section.RawSize;
            if (sectionIndex < ordered.Count - 1)
            {
                var oldLength = image.Length;
                var newLength = checked(oldLength + (int) growth);
                Array.Resize(ref image, newLength);

                Buffer.BlockCopy(
                    image,
                    checked((int) insertAt),
                    image,
                    checked((int) (insertAt + growth)),
                    checked(oldLength - (int) insertAt));
                Array.Clear(image, checked((int) insertAt), checked((int) growth));

                for (var i = sectionIndex + 1; i < ordered.Count; i++)
                {
                    var moved = ordered[i];
                    moved.RawPointer += growth;
                    WriteUInt32(image, moved.HeaderOffset + 20, moved.RawPointer);
                }

                Ctx.Options.Logger.Warning(
                    $"Expanded section '{section.Name}' raw data by 0x{growth:X} and shifted following sections to keep method body inside .text.");
            }
            else
            {
                var requiredLength = checked((int) (insertAt + growth));
                if (requiredLength > image.Length)
                    Array.Resize(ref image, requiredLength);
            }
        }

        private PeSection GetOrCreatePatchCodeSection(ref byte[] image, PeLayout layout)
        {
            var existing = layout.Sections.FirstOrDefault(s => s.Name == ".text#2");
            if (existing != null)
                return existing;

            var newHeaderOffset = layout.SectionTableOffset + layout.Sections.Count * 40;
            var firstRawPointer = layout.Sections.Min(s => s.RawPointer);
            if (newHeaderOffset + 40 > firstRawPointer)
            {
                var fallback = layout.Sections
                    .OrderBy(s => s.RawPointer + s.RawSize)
                    .LastOrDefault();
                if (fallback == null)
                    throw new DevirtualizationException("Not enough room in PE headers to add a new section.");

                Ctx.Options.Logger.Warning(
                    $"Not enough room in PE headers for .text#2; reusing existing section '{fallback.Name}' for relocated method body.");
                return fallback;
            }

            var newVirtualAddress = layout.Sections
                .Select(s => s.VirtualAddress + Align(Math.Max(s.VirtualSize, s.RawSize), layout.SectionAlignment))
                .Max();
            newVirtualAddress = Align(newVirtualAddress, layout.SectionAlignment);

            var newRawPointer = layout.Sections
                .Select(s => s.RawPointer + s.RawSize)
                .Max();
            newRawPointer = Align(newRawPointer, layout.FileAlignment);

            // Name (8 bytes)
            var nameBytes = new byte[8];
            var encoded = Encoding.ASCII.GetBytes(".text#2");
            Buffer.BlockCopy(encoded, 0, nameBytes, 0, encoded.Length);
            Buffer.BlockCopy(nameBytes, 0, image, newHeaderOffset, 8);

            WriteUInt32(image, newHeaderOffset + 8, 0); // VirtualSize
            WriteUInt32(image, newHeaderOffset + 12, newVirtualAddress);
            WriteUInt32(image, newHeaderOffset + 16, 0); // SizeOfRawData
            WriteUInt32(image, newHeaderOffset + 20, newRawPointer);
            WriteUInt32(image, newHeaderOffset + 24, 0);
            WriteUInt32(image, newHeaderOffset + 28, 0);
            WriteUInt16(image, newHeaderOffset + 32, 0);
            WriteUInt16(image, newHeaderOffset + 34, 0);
            WriteUInt32(image, newHeaderOffset + 36, 0x60000020); // code | execute | read

            layout.SectionCount++;
            WriteUInt16(image, layout.NumberOfSectionsOffset, (ushort) layout.SectionCount);

            var section = new PeSection(".text#2", newHeaderOffset, newVirtualAddress, 0, newRawPointer, 0);
            layout.Sections.Add(section);
            return section;
        }

        private void PatchMethodDefinitionRva(byte[] image, PeLayout layout, uint methodToken, uint newRva)
        {
            var info = GetMethodDefTableInfo(image, layout);
            var rid = methodToken & 0x00FFFFFF;
            if (rid == 0)
                throw new DevirtualizationException($"Invalid method token 0x{methodToken:X8}.");

            var rowIndex = checked((int) (rid - 1));
            var rowOffset = info.MethodTableOffset + rowIndex * info.MethodRowSize;
            if (rowOffset < 0 || rowOffset + 4 > image.Length)
                throw new DevirtualizationException($"MethodDef row offset out of bounds for token 0x{methodToken:X8}.");

            WriteUInt32(image, rowOffset, newRva);
        }

        private MethodDefTableInfo GetMethodDefTableInfo(byte[] image, PeLayout layout)
        {
            var metadataRva = ReadUInt32(image, layout.ClrHeaderFileOffset + 8);
            if (metadataRva == 0)
                throw new DevirtualizationException("CLR metadata RVA is zero.");

            var metadataOffset = RvaToFileOffset(layout, metadataRva);
            if (ReadUInt32(image, metadataOffset) != 0x424A5342) // BSJB
                throw new DevirtualizationException("Invalid CLR metadata signature.");

            var position = metadataOffset + 4; // signature
            position += 2; // major
            position += 2; // minor
            position += 4; // reserved
            var versionLength = ReadUInt32(image, position);
            position += 4;
            position += checked((int) versionLength);
            position = Align4(position);

            position += 2; // flags
            var streamCount = ReadUInt16(image, position);
            position += 2;

            int tablesStreamOffset = -1;
            for (var i = 0; i < streamCount; i++)
            {
                var streamOffset = ReadUInt32(image, position);
                position += 4;
                _ = ReadUInt32(image, position); // size
                position += 4;

                var nameStart = position;
                while (position < image.Length && image[position] != 0)
                    position++;
                var name = Encoding.ASCII.GetString(image, nameStart, position - nameStart);
                position++; // null terminator
                while (((position - nameStart) & 3) != 0)
                    position++;

                if (name == "#~" || name == "#-")
                    tablesStreamOffset = metadataOffset + checked((int) streamOffset);
            }

            if (tablesStreamOffset < 0)
                throw new DevirtualizationException("Could not locate metadata tables stream.");

            return ParseMethodDefTableInfo(image, tablesStreamOffset);
        }

        private MethodDefTableInfo ParseMethodDefTableInfo(byte[] image, int tablesOffset)
        {
            var position = tablesOffset;
            position += 4; // reserved
            position += 1; // major
            position += 1; // minor
            var heapSizes = image[position];
            position += 1;
            position += 1; // reserved
            var validMask = ReadUInt64(image, position);
            position += 8;
            position += 8; // sorted mask

            var rowCounts = new uint[64];
            for (var table = 0; table < 64; table++)
            {
                if (((validMask >> table) & 1UL) == 0)
                    continue;
                rowCounts[table] = ReadUInt32(image, position);
                position += 4;
            }

            var rowsOffset = position;
            var current = rowsOffset;
            for (var table = 0; table < 64; table++)
            {
                if (((validMask >> table) & 1UL) == 0)
                    continue;

                var rowSize = GetMetadataTableRowSize(table, rowCounts, heapSizes);
                if (table == 6) // MethodDef
                    return new MethodDefTableInfo(current, rowSize);

                current += checked((int) (rowCounts[table] * (uint) rowSize));
            }

            throw new DevirtualizationException("MethodDef table is missing from metadata.");
        }

        private MetadataTableInfo GetAssemblyTableInfo(byte[] image, PeLayout layout)
        {
            var metadataRva = ReadUInt32(image, layout.ClrHeaderFileOffset + 8);
            if (metadataRva == 0)
                throw new DevirtualizationException("CLR metadata RVA is zero.");

            var metadataOffset = RvaToFileOffset(layout, metadataRva);
            if (ReadUInt32(image, metadataOffset) != 0x424A5342) // BSJB
                throw new DevirtualizationException("Invalid CLR metadata signature.");

            var position = metadataOffset + 4; // signature
            position += 2; // major
            position += 2; // minor
            position += 4; // reserved
            var versionLength = ReadUInt32(image, position);
            position += 4;
            position += checked((int) versionLength);
            position = Align4(position);

            position += 2; // flags
            var streamCount = ReadUInt16(image, position);
            position += 2;

            var tablesStreamOffset = -1;
            for (var i = 0; i < streamCount; i++)
            {
                var streamOffset = ReadUInt32(image, position);
                position += 4;
                _ = ReadUInt32(image, position); // size
                position += 4;

                var nameStart = position;
                while (position < image.Length && image[position] != 0)
                    position++;
                var name = Encoding.ASCII.GetString(image, nameStart, position - nameStart);
                position++; // null terminator
                while (((position - nameStart) & 3) != 0)
                    position++;

                if (name == "#~" || name == "#-")
                    tablesStreamOffset = metadataOffset + checked((int) streamOffset);
            }

            if (tablesStreamOffset < 0)
                throw new DevirtualizationException("Could not locate metadata tables stream.");

            position = tablesStreamOffset;
            position += 4; // reserved
            position += 1; // major
            position += 1; // minor
            var heapSizes = image[position];
            position += 1;
            position += 1; // reserved
            var validMask = ReadUInt64(image, position);
            position += 8;
            position += 8; // sorted mask

            var rowCounts = new uint[64];
            for (var table = 0; table < 64; table++)
            {
                if (((validMask >> table) & 1UL) == 0)
                    continue;
                rowCounts[table] = ReadUInt32(image, position);
                position += 4;
            }

            var rowsOffset = position;
            var current = rowsOffset;
            for (var table = 0; table < 64; table++)
            {
                if (((validMask >> table) & 1UL) == 0)
                    continue;

                var rowSize = GetMetadataTableRowSize(table, rowCounts, heapSizes);
                if (table == 32) // Assembly
                {
                    return new MetadataTableInfo(
                        current,
                        rowSize,
                        rowCounts[table],
                        (heapSizes & 0x04) != 0 ? 4 : 2);
                }

                current += checked((int) (rowCounts[table] * (uint) rowSize));
            }

            throw new DevirtualizationException("Assembly table is missing from metadata.");
        }

        private int GetMetadataTableRowSize(int table, uint[] rowCounts, byte heapSizes)
        {
            var stringIndexSize = (heapSizes & 0x01) != 0 ? 4 : 2;
            var guidIndexSize = (heapSizes & 0x02) != 0 ? 4 : 2;
            var blobIndexSize = (heapSizes & 0x04) != 0 ? 4 : 2;

            int SimpleIndexSize(int targetTable) => rowCounts[targetTable] < 0x10000 ? 2 : 4;
            int CodedIndexSize(int tagBits, params int[] targetTables)
            {
                var maxRows = 0u;
                foreach (var t in targetTables)
                    maxRows = Math.Max(maxRows, rowCounts[t]);
                return maxRows < (1u << (16 - tagBits)) ? 2 : 4;
            }

            switch (table)
            {
                case 0: // Module
                    return 2 + stringIndexSize + guidIndexSize + guidIndexSize + guidIndexSize;
                case 1: // TypeRef
                    return CodedIndexSize(2, 0, 1, 26, 35) + stringIndexSize + stringIndexSize;
                case 2: // TypeDef
                    return 4 + stringIndexSize + stringIndexSize + CodedIndexSize(2, 1, 2, 27) +
                           SimpleIndexSize(4) + SimpleIndexSize(6);
                case 3: // FieldPtr
                    return SimpleIndexSize(4);
                case 4: // Field
                    return 2 + stringIndexSize + blobIndexSize;
                case 5: // MethodPtr
                    return SimpleIndexSize(6);
                case 6: // MethodDef
                    return 4 + 2 + 2 + stringIndexSize + blobIndexSize + SimpleIndexSize(8);
                case 7: // ParamPtr
                    return SimpleIndexSize(8);
                case 8: // Param
                    return 2 + 2 + stringIndexSize;
                case 9: // InterfaceImpl
                    return SimpleIndexSize(2) + CodedIndexSize(2, 1, 2, 27);
                case 10: // MemberRef
                    return CodedIndexSize(3, 2, 1, 26, 6, 27) + stringIndexSize + blobIndexSize;
                case 11: // Constant
                    return 2 + CodedIndexSize(2, 4, 8, 23) + blobIndexSize;
                case 12: // CustomAttribute
                    return CodedIndexSize(5, 6, 4, 1, 2, 8, 9, 10, 0, 14, 23, 20, 17, 26, 27, 32, 35, 38, 39, 40, 42, 44, 43) +
                           CodedIndexSize(3, 6, 10) + blobIndexSize;
                case 13: // FieldMarshal
                    return CodedIndexSize(1, 4, 8) + blobIndexSize;
                case 14: // DeclSecurity
                    return 2 + CodedIndexSize(2, 2, 6, 32) + blobIndexSize;
                case 15: // ClassLayout
                    return 2 + 4 + SimpleIndexSize(2);
                case 16: // FieldLayout
                    return 4 + SimpleIndexSize(4);
                case 17: // StandAloneSig
                    return blobIndexSize;
                case 18: // EventMap
                    return SimpleIndexSize(2) + SimpleIndexSize(20);
                case 19: // EventPtr
                    return SimpleIndexSize(20);
                case 20: // Event
                    return 2 + stringIndexSize + CodedIndexSize(2, 1, 2, 27);
                case 21: // PropertyMap
                    return SimpleIndexSize(2) + SimpleIndexSize(23);
                case 22: // PropertyPtr
                    return SimpleIndexSize(23);
                case 23: // Property
                    return 2 + stringIndexSize + blobIndexSize;
                case 24: // MethodSemantics
                    return 2 + SimpleIndexSize(6) + CodedIndexSize(1, 20, 23);
                case 25: // MethodImpl
                    return SimpleIndexSize(2) + CodedIndexSize(1, 6, 10) + CodedIndexSize(1, 6, 10);
                case 26: // ModuleRef
                    return stringIndexSize;
                case 27: // TypeSpec
                    return blobIndexSize;
                case 28: // ImplMap
                    return 2 + CodedIndexSize(1, 4, 6) + stringIndexSize + SimpleIndexSize(26);
                case 29: // FieldRva
                    return 4 + SimpleIndexSize(4);
                case 30: // ENCLog
                    return 8;
                case 31: // ENCMap
                    return 4;
                case 32: // Assembly
                    return 4 + 2 + 2 + 2 + 2 + 4 + blobIndexSize + stringIndexSize + stringIndexSize;
                case 33: // AssemblyProcessor
                    return 4;
                case 34: // AssemblyOS
                    return 12;
                case 35: // AssemblyRef
                    return 2 + 2 + 2 + 2 + 4 + blobIndexSize + stringIndexSize + stringIndexSize + blobIndexSize;
                case 36: // AssemblyRefProcessor
                    return 4 + SimpleIndexSize(35);
                case 37: // AssemblyRefOS
                    return 12 + SimpleIndexSize(35);
                case 38: // File
                    return 4 + stringIndexSize + blobIndexSize;
                case 39: // ExportedType
                    return 4 + 4 + stringIndexSize + stringIndexSize + CodedIndexSize(2, 38, 35, 39);
                case 40: // ManifestResource
                    return 4 + 4 + stringIndexSize + CodedIndexSize(2, 38, 35, 39);
                case 41: // NestedClass
                    return SimpleIndexSize(2) + SimpleIndexSize(2);
                case 42: // GenericParam
                    return 2 + 2 + CodedIndexSize(1, 2, 6) + stringIndexSize;
                case 43: // MethodSpec
                    return CodedIndexSize(1, 6, 10) + blobIndexSize;
                case 44: // GenericParamConstraint
                    return SimpleIndexSize(42) + CodedIndexSize(2, 1, 2, 27);
                default:
                    throw new DevirtualizationException(
                        $"Unsupported metadata table {table} while locating MethodDef table.");
            }
        }

        private uint ReadUInt32(byte[] data, int offset) => BitConverter.ToUInt32(data, offset);
        private ushort ReadUInt16(byte[] data, int offset) => BitConverter.ToUInt16(data, offset);
        private ulong ReadUInt64(byte[] data, int offset) => BitConverter.ToUInt64(data, offset);

        private void WriteUInt32(byte[] data, int offset, uint value)
        {
            var bytes = BitConverter.GetBytes(value);
            Buffer.BlockCopy(bytes, 0, data, offset, 4);
        }

        private void WriteUInt16(byte[] data, int offset, ushort value)
        {
            var bytes = BitConverter.GetBytes(value);
            Buffer.BlockCopy(bytes, 0, data, offset, 2);
        }

        private PeLayout ReadPeLayout(byte[] image)
        {
            using var ms = new MemoryStream(image, false);
            using var br = new BinaryReader(ms, Encoding.UTF8, true);

            if (br.ReadUInt16() != 0x5A4D)
                throw new DevirtualizationException("Invalid DOS header.");

            ms.Position = 0x3C;
            var peOffset = br.ReadInt32();
            ms.Position = peOffset;
            if (br.ReadUInt32() != 0x00004550)
                throw new DevirtualizationException("Invalid PE signature.");

            _ = br.ReadUInt16(); // machine
            var numberOfSectionsOffset = checked((int) ms.Position);
            var numberOfSections = br.ReadUInt16();
            ms.Position += 12;
            var optionalHeaderSize = br.ReadUInt16();
            ms.Position += 2;

            var optionalHeaderStart = ms.Position;
            var magic = br.ReadUInt16();
            var isPe32Plus = magic == 0x20B;
            ms.Position = optionalHeaderStart + 32;
            var sectionAlignment = br.ReadUInt32();
            var fileAlignment = br.ReadUInt32();
            ms.Position = optionalHeaderStart + 56;
            _ = br.ReadUInt32(); // size of image
            var sizeOfImageOffset = checked((int) (optionalHeaderStart + 56));

            var dataDirectoryStart = optionalHeaderStart + (isPe32Plus ? 112 : 96);
            var clrDirectoryOffset = dataDirectoryStart + 14 * 8;
            ms.Position = clrDirectoryOffset;
            var clrRva = br.ReadUInt32();
            var clrHeaderFileOffset = clrRva == 0 ? 0 : RvaToOffsetForLayoutRead(ms, br, optionalHeaderStart, optionalHeaderSize, numberOfSections, clrRva);

            ms.Position = optionalHeaderStart + optionalHeaderSize;
            var sectionTableOffset = checked((int) ms.Position);

            var sections = new List<PeSection>(numberOfSections);
            for (var i = 0; i < numberOfSections; i++)
            {
                var sectionHeaderOffset = checked((int) ms.Position);
                var name = Encoding.ASCII.GetString(br.ReadBytes(8)).Trim('\0'); // name
                var virtualSize = br.ReadUInt32();
                var virtualAddress = br.ReadUInt32();
                var rawSize = br.ReadUInt32();
                var rawPointer = br.ReadUInt32();
                ms.Position += 16;

                sections.Add(new PeSection(name, sectionHeaderOffset, virtualAddress, virtualSize, rawPointer, rawSize));
            }

            return new PeLayout(
                sections,
                fileAlignment,
                sectionAlignment,
                sizeOfImageOffset,
                checked((int) clrHeaderFileOffset),
                sectionTableOffset,
                numberOfSectionsOffset);
        }

        private uint RvaToOffsetForLayoutRead(
            MemoryStream ms,
            BinaryReader br,
            long optionalHeaderStart,
            ushort optionalHeaderSize,
            ushort numberOfSections,
            uint rva)
        {
            var sectionTableStart = optionalHeaderStart + optionalHeaderSize;
            for (var i = 0; i < numberOfSections; i++)
            {
                ms.Position = sectionTableStart + i * 40;
                _ = br.ReadBytes(8);
                var virtualSize = br.ReadUInt32();
                var virtualAddress = br.ReadUInt32();
                var rawSize = br.ReadUInt32();
                var rawPointer = br.ReadUInt32();
                ms.Position += 16;

                var sectionSpan = Math.Max(virtualSize, rawSize);
                if (rva >= virtualAddress && rva < virtualAddress + sectionSpan)
                    return rawPointer + (rva - virtualAddress);
            }

            throw new DevirtualizationException($"Could not map RVA 0x{rva:X8} while reading PE layout.");
        }

        private sealed class PeLayout
        {
            public PeLayout(
                List<PeSection> sections,
                uint fileAlignment,
                uint sectionAlignment,
                int sizeOfImageOffset,
                int clrHeaderFileOffset,
                int sectionTableOffset,
                int numberOfSectionsOffset)
            {
                Sections = sections;
                FileAlignment = fileAlignment;
                SectionAlignment = sectionAlignment;
                SizeOfImageOffset = sizeOfImageOffset;
                ClrHeaderFileOffset = clrHeaderFileOffset;
                SectionTableOffset = sectionTableOffset;
                NumberOfSectionsOffset = numberOfSectionsOffset;
                SectionCount = sections.Count;
            }

            public List<PeSection> Sections { get; }
            public uint FileAlignment { get; }
            public uint SectionAlignment { get; }
            public int SizeOfImageOffset { get; }
            public int ClrHeaderFileOffset { get; }
            public int SectionTableOffset { get; }
            public int NumberOfSectionsOffset { get; }
            public int SectionCount { get; set; }
        }

        private sealed class PeSection
        {
            public PeSection(string name, int headerOffset, uint virtualAddress, uint virtualSize, uint rawPointer, uint rawSize)
            {
                Name = name;
                HeaderOffset = headerOffset;
                VirtualAddress = virtualAddress;
                VirtualSize = virtualSize;
                RawPointer = rawPointer;
                RawSize = rawSize;
            }

            public string Name { get; }
            public int HeaderOffset { get; }
            public uint VirtualAddress { get; }
            public uint VirtualSize { get; set; }
            public uint RawPointer { get; set; }
            public uint RawSize { get; set; }
        }

        private sealed class MethodDefTableInfo
        {
            public MethodDefTableInfo(int methodTableOffset, int methodRowSize)
            {
                MethodTableOffset = methodTableOffset;
                MethodRowSize = methodRowSize;
            }

            public int MethodTableOffset { get; }
            public int MethodRowSize { get; }
        }

        private sealed class MetadataTableInfo
        {
            public MetadataTableInfo(int tableOffset, int rowSize, uint rowCount, int blobIndexSize)
            {
                TableOffset = tableOffset;
                RowSize = rowSize;
                RowCount = rowCount;
                BlobIndexSize = blobIndexSize;
            }

            public int TableOffset { get; }
            public int RowSize { get; }
            public uint RowCount { get; }
            public int BlobIndexSize { get; }
        }

        private void NormalizeAssemblyIdentity(AsmResolver.DotNet.ModuleDefinition module)
        {
            module.IsStrongNameSigned = false;
            if (module.Assembly != null)
            {
                module.Assembly.PublicKey = null;
                module.Assembly.HasPublicKey = false;
            }
        }

        private int RepairInvalidTypeReferences(AsmResolver.DotNet.ModuleDefinition module, string sourcePath)
        {
            try
            {
                using var stream = File.OpenRead(sourcePath);
                using var pe = new PEReader(stream, PEStreamOptions.PrefetchMetadata);
                var metadata = pe.GetMetadataReader();

                AsmResolver.DotNet.IResolutionScope fallbackScope = module;

                var repaired = 0;
                for (var rid = 1; rid <= metadata.TypeReferences.Count; rid++)
                {
                    var token = unchecked((int) (0x01000000u | (uint) rid));
                    AsmResolver.DotNet.ITypeDefOrRef member;
                    try
                    {
                        member = module.LookupMember(token) as AsmResolver.DotNet.ITypeDefOrRef;
                    }
                    catch
                    {
                        continue;
                    }

                    if (!(member is AsmResolver.DotNet.TypeReference typeRef))
                        continue;

                    var needsRepair = false;
                    try
                    {
                        _ = typeRef.Scope;
                    }
                    catch
                    {
                        needsRepair = true;
                    }

                    if (!needsRepair && typeRef.Scope != null)
                        continue;

                    try
                    {
                        var currentName = typeRef.Name?.ToString();
                        if (string.IsNullOrEmpty(currentName))
                            typeRef.Name = "Object";
                        if (ReferenceEquals(typeRef.Namespace, null))
                            typeRef.Namespace = string.Empty;
                        typeRef.Scope = fallbackScope;
                        repaired++;
                    }
                    catch
                    {
                        // Best effort repair only.
                    }
                }

                return repaired;
            }
            catch
            {
                return 0;
            }
        }

        private int SanitizeHashtableCapacityConstructors(AsmResolver.DotNet.ModuleDefinition module)
        {
            var patched = 0;
            foreach (var type in module.GetAllTypes())
            {
                foreach (var method in type.Methods)
                {
                    var body = method.CilMethodBody;
                    if (body == null)
                        continue;

                    for (var i = 0; i < body.Instructions.Count; i++)
                    {
                        var instruction = body.Instructions[i];
                        if (instruction.OpCode.Code != CilCode.Newobj ||
                            !(instruction.Operand is IMethodDescriptor descriptor))
                            continue;

                        if (!IsHashtableIntCapacityCtor(descriptor))
                            continue;

                        if (HasHashtableCapacityClamp(body, i))
                            continue;

                        var keepOriginalCapacity = new CilInstruction(CilOpCodes.Nop);
                        body.Instructions.Insert(i, new CilInstruction(CilOpCodes.Dup));
                        body.Instructions.Insert(i + 1, new CilInstruction(CilOpCodes.Ldc_I4_0));
                        body.Instructions.Insert(
                            i + 2,
                            new CilInstruction(CilOpCodes.Bge, new CilInstructionLabel(keepOriginalCapacity)));
                        body.Instructions.Insert(i + 3, new CilInstruction(CilOpCodes.Pop));
                        body.Instructions.Insert(i + 4, new CilInstruction(CilOpCodes.Ldc_I4_0));
                        body.Instructions.Insert(i + 5, keepOriginalCapacity);

                        i += 6;
                        patched++;
                    }
                }
            }

            return patched;
        }

        private bool HasHashtableCapacityClamp(CilMethodBody body, int newobjIndex)
        {
            if (newobjIndex < 6)
                return false;

            var first = body.Instructions[newobjIndex - 6];
            var second = body.Instructions[newobjIndex - 5];
            var third = body.Instructions[newobjIndex - 4];
            var fourth = body.Instructions[newobjIndex - 3];
            var fifth = body.Instructions[newobjIndex - 2];
            var target = body.Instructions[newobjIndex - 1];

            if (first.OpCode.Code != CilCode.Dup)
                return false;
            if (!IsLdcI4Zero(second))
                return false;
            if (third.OpCode.Code != CilCode.Bge && third.OpCode.Code != CilCode.Bge_S)
                return false;
            if (fourth.OpCode.Code != CilCode.Pop)
                return false;
            if (!IsLdcI4Zero(fifth))
                return false;
            if (!(third.Operand is CilInstructionLabel label))
                return false;

            return ReferenceEquals(label.Instruction, target);
        }

        private bool IsHashtableIntCapacityCtor(IMethodDescriptor descriptor)
        {
            if (descriptor == null)
                return false;

            AsmResolver.DotNet.MethodDefinition resolved = null;
            try
            {
                resolved = descriptor.Resolve();
            }
            catch
            {
                // Resolution may fail for malformed metadata. Fall back to signature checks only.
            }

            var declaringTypeFullName = descriptor.DeclaringType?.FullName ?? resolved?.DeclaringType?.FullName;
            if (!string.Equals(declaringTypeFullName, "System.Collections.Hashtable", StringComparison.Ordinal))
                return false;

            var signature = descriptor.Signature ?? resolved?.Signature;
            return signature?.ParameterTypes.Count == 1 &&
                   string.Equals(signature.ParameterTypes[0].FullName, "System.Int32", StringComparison.Ordinal);
        }

        private bool IsLdcI4Zero(CilInstruction instruction)
        {
            switch (instruction.OpCode.Code)
            {
                case CilCode.Ldc_I4_0:
                    return true;
                case CilCode.Ldc_I4:
                    return instruction.Operand is int fullInt && fullInt == 0;
                case CilCode.Ldc_I4_S:
                    return instruction.Operand is sbyte shortInt && shortInt == 0;
                default:
                    return false;
            }
        }

        private bool GetFeatureToggle(string enableVariableName, bool defaultEnabled, string disableVariableName = null)
        {
            if (!string.IsNullOrWhiteSpace(disableVariableName) &&
                TryGetEnvironmentToggle(disableVariableName, out var isDisabled) &&
                isDisabled)
            {
                return false;
            }

            if (TryGetEnvironmentToggle(enableVariableName, out var isEnabled))
                return isEnabled;

            return defaultEnabled;
        }

        private bool TryGetEnvironmentToggle(string variableName, out bool value)
        {
            var raw = Environment.GetEnvironmentVariable(variableName);
            if (string.IsNullOrWhiteSpace(raw))
            {
                value = false;
                return false;
            }

            raw = raw.Trim();
            if (string.Equals(raw, "1", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(raw, "true", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(raw, "yes", StringComparison.OrdinalIgnoreCase))
            {
                value = true;
                return true;
            }

            if (string.Equals(raw, "0", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(raw, "false", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(raw, "no", StringComparison.OrdinalIgnoreCase))
            {
                value = false;
                return true;
            }

            value = false;
            return false;
        }

        private int BypassWindowsFormsEntryGuards(AsmResolver.DotNet.ModuleDefinition module)
        {
            var patched = 0;
            foreach (var type in module.GetAllTypes())
            {
                if (!IsWindowsFormsFormType(type))
                    continue;

                foreach (var method in type.Methods)
                {
                    if (method.CilMethodBody == null)
                        continue;
                    if (!TryPatchLeadingBooleanGuard(method.CilMethodBody))
                        continue;

                    patched++;
                }
            }

            return patched;
        }

        private bool IsWindowsFormsFormType(AsmResolver.DotNet.TypeDefinition type)
        {
            var depth = 0;
            var current = type;
            while (current != null && depth++ < 16)
            {
                var baseType = current.BaseType;
                if (baseType == null)
                    return false;
                if (string.Equals(baseType.FullName, "System.Windows.Forms.Form", StringComparison.Ordinal))
                    return true;

                current = baseType.Resolve();
            }

            return false;
        }

        private bool TryPatchLeadingBooleanGuard(CilMethodBody body)
        {
            if (body.Instructions.Count < 3)
                return false;

            var first = body.Instructions[0];
            var second = body.Instructions[1];
            var third = body.Instructions[2];
            if (!IsLdcI4(first))
                return false;
            if (!IsInt32ToBooleanCall(second))
                return false;
            if (third.OpCode.Code != CilCode.Brfalse && third.OpCode.Code != CilCode.Brfalse_S)
                return false;
            if (!(third.Operand is CilInstructionLabel target) || target.Instruction == null ||
                target.Instruction.OpCode.Code != CilCode.Ret)
                return false;

            body.Instructions[0] = new CilInstruction(CilOpCodes.Nop);
            body.Instructions[1] = new CilInstruction(CilOpCodes.Ldc_I4_1);
            return true;
        }

        private bool IsLdcI4(CilInstruction instruction)
        {
            switch (instruction.OpCode.Code)
            {
                case CilCode.Ldc_I4_M1:
                case CilCode.Ldc_I4_0:
                case CilCode.Ldc_I4_1:
                case CilCode.Ldc_I4_2:
                case CilCode.Ldc_I4_3:
                case CilCode.Ldc_I4_4:
                case CilCode.Ldc_I4_5:
                case CilCode.Ldc_I4_6:
                case CilCode.Ldc_I4_7:
                case CilCode.Ldc_I4_8:
                case CilCode.Ldc_I4_S:
                case CilCode.Ldc_I4:
                    return true;
                default:
                    return false;
            }
        }

        private bool IsInt32ToBooleanCall(CilInstruction instruction)
        {
            if (instruction.OpCode.Code != CilCode.Call && instruction.OpCode.Code != CilCode.Callvirt)
                return false;
            if (!(instruction.Operand is IMethodDescriptor descriptor))
                return false;

            var signature = descriptor.Signature ?? descriptor.Resolve()?.Signature;
            return signature != null &&
                   string.Equals(signature.ReturnType?.FullName, "System.Boolean", StringComparison.Ordinal) &&
                   signature.ParameterTypes.Count == 1 &&
                   string.Equals(signature.ParameterTypes[0].FullName, "System.Int32", StringComparison.Ordinal);
        }

        private IEnumerable<AsmResolver.DotNet.TypeDefinition> GetBootstrapCandidateTypes(
            IEnumerable<Core.Architecture.VMMethod> methodsToPatch)
        {
            var candidates = new HashSet<AsmResolver.DotNet.TypeDefinition>();

            var entryType = Ctx.Module.ManagedEntryPointMethod?.DeclaringType;
            if (entryType != null)
                candidates.Add(entryType);

            var entryPoint = Ctx.Module.ManagedEntryPointMethod;
            if (entryPoint?.CilMethodBody != null)
            {
                foreach (var instruction in entryPoint.CilMethodBody.Instructions)
                {
                    if (instruction.OpCode.Code != CilCode.Call && instruction.OpCode.Code != CilCode.Callvirt)
                        continue;
                    if (!(instruction.Operand is IMethodDescriptor callee))
                        continue;

                    var calleeType = callee.Resolve()?.DeclaringType;
                    if (calleeType != null)
                        candidates.Add(calleeType);
                }
            }

            var moduleType = Ctx.Module.GetAllTypes().FirstOrDefault(t =>
                string.Equals(t.Name, "<Module>", StringComparison.Ordinal));
            if (moduleType != null)
                candidates.Add(moduleType);

            foreach (var vmMethod in methodsToPatch)
            {
                var declaringType = vmMethod.Parent?.DeclaringType;
                if (declaringType != null)
                    candidates.Add(declaringType);
            }

            return candidates;
        }

        private int NeutralizeSharedBootstrapMethods(AsmResolver.DotNet.ModuleDefinition module)
        {
            var callCounts = new Dictionary<AsmResolver.DotNet.MethodDefinition, int>();

            foreach (var type in module.GetAllTypes())
            {
                var cctor = type.Methods.FirstOrDefault(m =>
                    m.Name == ".cctor" && m.IsStatic && m.CilMethodBody != null);
                if (cctor?.CilMethodBody == null)
                    continue;

                var instructions = cctor.CilMethodBody.Instructions;
                if (instructions.Count < 1 || instructions.Count > 8)
                    continue;

                var firstCall = instructions.FirstOrDefault(i =>
                    i.OpCode.Code == CilCode.Call || i.OpCode.Code == CilCode.Callvirt);
                var callee = firstCall?.Operand as IMethodDescriptor;
                if (callee == null)
                    continue;

                AsmResolver.DotNet.MethodDefinition calleeDef;
                try
                {
                    calleeDef = callee.Resolve();
                }
                catch
                {
                    continue;
                }

                if (calleeDef?.CilMethodBody == null)
                    continue;
                if (!string.Equals(calleeDef.Signature?.ReturnType?.FullName, "System.Void", StringComparison.Ordinal))
                    continue;
                if (calleeDef.Signature.ParameterTypes.Count != 0)
                    continue;
                if (!LooksLikeSharedBootstrapWorker(calleeDef))
                    continue;

                if (!callCounts.TryGetValue(calleeDef, out var count))
                    count = 0;
                callCounts[calleeDef] = count + 1;
            }

            var patched = 0;
            foreach (var kv in callCounts.Where(kv => kv.Value >= 3))
            {
                var method = kv.Key;
                if (method.CilMethodBody == null)
                    continue;

                var replacement = new CilMethodBody(method)
                {
                    InitializeLocals = false,
                    ComputeMaxStackOnBuild = true,
                    MaxStack = 1
                };
                replacement.Instructions.Add(new CilInstruction(CilOpCodes.Ret));
                method.CilMethodBody = replacement;
                patched++;
            }

            return patched;
        }

        private bool LooksLikeSharedBootstrapWorker(AsmResolver.DotNet.MethodDefinition method)
        {
            var body = method.CilMethodBody;
            if (body == null)
                return false;

            var largeAndObfuscated =
                body.Instructions.Count >= 500 ||
                body.LocalVariables.Count >= 64 ||
                body.ExceptionHandlers.Count >= 8;
            if (!largeAndObfuscated)
                return false;

            return ContainsHashtableCapacityCtor(body);
        }

        private bool ContainsHashtableCapacityCtor(CilMethodBody body)
        {
            foreach (var instruction in body.Instructions)
            {
                if (instruction.OpCode.Code != CilCode.Newobj ||
                    !(instruction.Operand is IMethodDescriptor descriptor))
                    continue;

                if (IsHashtableIntCapacityCtor(descriptor))
                    return true;
            }

            return false;
        }

        private int DisableBootstrapTypeInitializers(
            AsmResolver.DotNet.ModuleDefinition module,
            IEnumerable<AsmResolver.DotNet.TypeDefinition> candidateTypes)
        {
            var patched = 0;
            foreach (var type in candidateTypes)
            {
                var cctor = type.Methods.FirstOrDefault(m =>
                    m.Name == ".cctor" && m.IsStatic && m.CilMethodBody != null);
                if (cctor?.CilMethodBody == null)
                    continue;
                if (!LooksLikeBootstrapTypeInitializer(cctor))
                    continue;

                var replacement = new CilMethodBody(cctor)
                {
                    InitializeLocals = false,
                    ComputeMaxStackOnBuild = true,
                    MaxStack = 1
                };
                replacement.Instructions.Add(new CilInstruction(CilOpCodes.Ret));
                cctor.CilMethodBody = replacement;
                patched++;
            }

            return patched;
        }

        private bool LooksLikeBootstrapTypeInitializer(AsmResolver.DotNet.MethodDefinition cctor)
        {
            var instructions = cctor.CilMethodBody.Instructions;
            if (instructions.Count < 1 || instructions.Count > 3)
                return false;

            var first = instructions[0];
            if (first.OpCode.Code != CilCode.Call && first.OpCode.Code != CilCode.Callvirt)
                return false;

            if (!(first.Operand is IMethodDescriptor callee))
                return false;

            var calleeDef = callee.Resolve();
            var calleeBody = calleeDef?.CilMethodBody;
            if (calleeBody == null)
                return false;

            // Generic heuristic for protector bootstrap stubs:
            // tiny .cctor -> one call -> huge obfuscated bootstrap method.
            return calleeBody.Instructions.Count >= 500 ||
                   calleeBody.LocalVariables.Count >= 64 ||
                   calleeBody.ExceptionHandlers.Count >= 8;
        }

        private int StripMalformedCustomAttributes(AsmResolver.DotNet.ModuleDefinition module)
        {
            var removed = 0;

            removed += RemoveMalformedAttributes(module);

            if (module.Assembly != null)
                removed += RemoveMalformedAttributes(module.Assembly);

            foreach (var type in module.GetAllTypes())
            {
                removed += RemoveMalformedAttributes(type);

                foreach (var genericParameter in type.GenericParameters)
                    removed += RemoveMalformedAttributes(genericParameter);

                foreach (var field in type.Fields)
                {
                    removed += RemoveMalformedAttributes(field);
                }

                foreach (var method in type.Methods)
                {
                    removed += RemoveMalformedAttributes(method);

                    foreach (var parameter in method.ParameterDefinitions)
                        removed += RemoveMalformedAttributes(parameter);

                    foreach (var genericParameter in method.GenericParameters)
                        removed += RemoveMalformedAttributes(genericParameter);
                }

                foreach (var property in type.Properties)
                {
                    removed += RemoveMalformedAttributes(property);
                }

                foreach (var evt in type.Events)
                {
                    removed += RemoveMalformedAttributes(evt);
                }
            }

            return removed;
        }

        private int ClearAllCustomAttributes(AsmResolver.DotNet.ModuleDefinition module)
        {
            var removed = 0;

            removed += ClearAttributes(module);

            if (module.Assembly != null)
                removed += ClearAttributes(module.Assembly);

            foreach (var type in module.GetAllTypes())
            {
                removed += ClearAttributes(type);

                foreach (var genericParameter in type.GenericParameters)
                    removed += ClearAttributes(genericParameter);

                foreach (var field in type.Fields)
                {
                    removed += ClearAttributes(field);
                }

                foreach (var method in type.Methods)
                {
                    removed += ClearAttributes(method);

                    foreach (var parameter in method.ParameterDefinitions)
                        removed += ClearAttributes(parameter);

                    foreach (var genericParameter in method.GenericParameters)
                        removed += ClearAttributes(genericParameter);
                }

                foreach (var property in type.Properties)
                {
                    removed += ClearAttributes(property);
                }

                foreach (var evt in type.Events)
                {
                    removed += ClearAttributes(evt);
                }
            }

            return removed;
        }

        private int RemoveMalformedAttributes(AsmResolver.DotNet.IHasCustomAttribute provider)
        {
            if (provider == null || provider.CustomAttributes == null || provider.CustomAttributes.Count == 0)
                return 0;

            // AsmResolver crashes on some malformed custom attribute blobs in this challenge family.
            // Keep this aggressive for method/field/parameter scopes where obfuscators inject unstable data.
            if (provider is AsmResolver.DotNet.FieldDefinition ||
                provider is AsmResolver.DotNet.MethodDefinition ||
                provider is ParameterDefinition)
            {
                var all = provider.CustomAttributes.Count;
                provider.CustomAttributes.Clear();
                return all;
            }

            var removed = 0;
            for (var i = provider.CustomAttributes.Count - 1; i >= 0; i--)
            {
                if (!ShouldRemoveCustomAttribute(provider.CustomAttributes[i]))
                    continue;

                provider.CustomAttributes.RemoveAt(i);
                removed++;
            }

            return removed;
        }

        private bool ShouldRemoveCustomAttribute(AsmResolver.DotNet.CustomAttribute attribute)
        {
            try
            {
                return IsMalformedCustomAttribute(attribute);
            }
            catch
            {
                return true;
            }
        }

        private int ClearAttributes(AsmResolver.DotNet.IHasCustomAttribute provider)
        {
            if (provider == null || provider.CustomAttributes == null || provider.CustomAttributes.Count == 0)
                return 0;

            var count = provider.CustomAttributes.Count;
            provider.CustomAttributes.Clear();
            return count;
        }

        private bool IsMalformedCustomAttribute(AsmResolver.DotNet.CustomAttribute attribute)
        {
            if (attribute == null || attribute.Constructor == null || attribute.Signature == null)
                return true;

            foreach (var fixedArg in attribute.Signature.FixedArguments)
            {
                if (fixedArg == null || fixedArg.ArgumentType == null)
                    return true;
            }

            foreach (var namedArg in attribute.Signature.NamedArguments)
            {
                if (namedArg == null || namedArg.ArgumentType == null || namedArg.Argument == null ||
                    namedArg.Argument.ArgumentType == null)
                    return true;
            }

            return false;
        }

        private void ClearInvalidStrongNameFlag(string path)
        {
            byte[] image;
            try
            {
                image = File.ReadAllBytes(path);
            }
            catch
            {
                return;
            }

            try
            {
                var layout = ReadPeLayout(image);
                if (layout.ClrHeaderFileOffset <= 0 || layout.ClrHeaderFileOffset + 40 > image.Length)
                    return;

                // Clear COMIMAGE_FLAGS_STRONGNAMESIGNED in IMAGE_COR20_HEADER::Flags.
                var corFlagsOffset = layout.ClrHeaderFileOffset + 16;
                var corFlags = ReadUInt32(image, corFlagsOffset);
                WriteUInt32(image, corFlagsOffset, corFlags & ~0x8U);

                // Clear IMAGE_COR20_HEADER::StrongNameSignature directory RVA/Size.
                var strongNameDirectoryOffset = layout.ClrHeaderFileOffset + 32;
                WriteUInt32(image, strongNameDirectoryOffset, 0);
                WriteUInt32(image, strongNameDirectoryOffset + 4, 0);

                // Clear Assembly table HasPublicKey bit and zero PublicKey blob index.
                var assemblyTable = GetAssemblyTableInfo(image, layout);
                if (assemblyTable.RowCount > 0)
                {
                    var rowOffset = assemblyTable.TableOffset;
                    var assemblyFlagsOffset = rowOffset + 12;
                    var assemblyFlags = ReadUInt32(image, assemblyFlagsOffset);
                    WriteUInt32(image, assemblyFlagsOffset, assemblyFlags & ~0x1U);

                    var publicKeyIndexOffset = rowOffset + 16;
                    if (assemblyTable.BlobIndexSize == 2)
                        WriteUInt16(image, publicKeyIndexOffset, 0);
                    else
                        WriteUInt32(image, publicKeyIndexOffset, 0);
                }

                File.WriteAllBytes(path, image);
            }
            catch
            {
                // Best-effort cleanup only.
            }
        }

        private string FormatInstruction(Core.Architecture.VMInstruction instruction)
        {
            var line = instruction.ToString();
            if (instruction.Operand is int[] intArray)
            {
                var preview = string.Join(", ", intArray.Take(24));
                if (intArray.Length > 24)
                    preview += ", ...";
                return line + $" // targets[{intArray.Length}]: {preview}";
            }

            if (!(instruction.Operand is int))
                return line;

            var token = (int) instruction.Operand;
            if (token <= 0)
                return line;

            try
            {
                var member = Ctx.Module.LookupMember(token);
                if (member != null)
                    line += $" // {member}";
            }
            catch
            {
                // Non-metadata operands (or transformed tokens) are expected for many VM instructions.
            }

            return line;
        }

        private IEnumerable<string> GetHandlerSnippet(int vmByte)
        {
            if (Ctx.OpcodeHandlerMethod == null || Ctx.OpcodeHandlerIndices == null)
                return new[] {"<handler map unavailable>"};

            if (!Ctx.OpcodeHandlerIndices.TryGetValue(vmByte, out var index))
                return new[] {"<handler not found>"};

            var instructions = Ctx.OpcodeHandlerMethod.CilMethodBody.Instructions;
            var lines = new List<string>();
            for (var i = index; i < instructions.Count && lines.Count < 22; i++)
            {
                var instruction = instructions[i];
                var operand = instruction.Operand == null ? string.Empty : " " + instruction.Operand;
                lines.Add($"[{i}] {instruction.OpCode}{operand}");
                if (instruction.OpCode == AsmResolver.PE.DotNet.Cil.CilOpCodes.Ret)
                    break;
            }

            return lines;
        }
    }
}
