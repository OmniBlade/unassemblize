#include "function.h"
#include <Zydis/Zydis.h>
#include <zycore/Format.h>
#include <inttypes.h>
#include <sstream>

namespace
{
// Copy of the disassmble function without any formatting.
static ZyanStatus UnasmDisassembleNoFormat(ZydisMachineMode machine_mode, ZyanU64 runtime_address, const void *buffer,
    ZyanUSize length, ZydisDisassembledInstruction *instruction)
{
    if (!buffer || !instruction) {
        return ZYAN_STATUS_INVALID_ARGUMENT;
    }

    memset(instruction, 0, sizeof(*instruction));
    instruction->runtime_address = runtime_address;

    // Derive the stack width from the address width.
    ZydisStackWidth stack_width;
    switch (machine_mode) {
        case ZYDIS_MACHINE_MODE_LONG_64:
            stack_width = ZYDIS_STACK_WIDTH_64;
            break;
        case ZYDIS_MACHINE_MODE_LONG_COMPAT_32:
        case ZYDIS_MACHINE_MODE_LEGACY_32:
            stack_width = ZYDIS_STACK_WIDTH_32;
            break;
        case ZYDIS_MACHINE_MODE_LONG_COMPAT_16:
        case ZYDIS_MACHINE_MODE_LEGACY_16:
        case ZYDIS_MACHINE_MODE_REAL_16:
            stack_width = ZYDIS_STACK_WIDTH_16;
            break;
        default:
            return ZYAN_STATUS_INVALID_ARGUMENT;
    }

    ZydisDecoder decoder;
    ZYAN_CHECK(ZydisDecoderInit(&decoder, machine_mode, stack_width));

    ZydisDecoderContext ctx;
    ZYAN_CHECK(ZydisDecoderDecodeInstruction(&decoder, &ctx, buffer, length, &instruction->info));
    ZYAN_CHECK(ZydisDecoderDecodeOperands(
        &decoder, &ctx, &instruction->info, instruction->operands, instruction->info.operand_count));

    return ZYAN_STATUS_SUCCESS;
}

ZydisFormatterFunc default_print_address_absolute;

static ZyanStatus UnasmFormatterPrintAddressAbsolute(
    const ZydisFormatter *formatter, ZydisFormatterBuffer *buffer, ZydisFormatterContext *context)
{
    unassemblize::Function *func = static_cast <unassemblize::Function*>(context->user_data);
    uint64_t address;
    ZYAN_CHECK(ZydisCalcAbsoluteAddress(context->instruction, context->operand, context->runtime_address, &address));

    if (func->labels().find(address) != func->labels().end()) {
        ZYAN_CHECK(ZydisFormatterBufferAppend(buffer, ZYDIS_TOKEN_SYMBOL));
        ZyanString *string;
        ZYAN_CHECK(ZydisFormatterBufferGetString(buffer, &string));
        auto it = func->labels().find(address);
        return ZyanStringAppendFormat(string, "%s", it->second.c_str());
    } else if (address >= func->section_address() && address <= func->section_end()) {
        // Probably a function if the address is in the current section.
        ZYAN_CHECK(ZydisFormatterBufferAppend(buffer, ZYDIS_TOKEN_SYMBOL));
        ZyanString *string;
        ZYAN_CHECK(ZydisFormatterBufferGetString(buffer, &string));
        return ZyanStringAppendFormat(string, "sub_%x", address);
    }

    return default_print_address_absolute(formatter, buffer, context);
}

static ZyanStatus UnasmDisassembleCustom(ZydisMachineMode machine_mode, ZyanU64 runtime_address, const void *buffer,
    ZyanUSize length, ZydisDisassembledInstruction *instruction, void *user_data)
{
    if (!buffer || !instruction) {
        return ZYAN_STATUS_INVALID_ARGUMENT;
    }

    memset(instruction, 0, sizeof(*instruction));
    instruction->runtime_address = runtime_address;

    // Derive the stack width from the address width.
    ZydisStackWidth stack_width;
    switch (machine_mode) {
        case ZYDIS_MACHINE_MODE_LONG_64:
            stack_width = ZYDIS_STACK_WIDTH_64;
            break;
        case ZYDIS_MACHINE_MODE_LONG_COMPAT_32:
        case ZYDIS_MACHINE_MODE_LEGACY_32:
            stack_width = ZYDIS_STACK_WIDTH_32;
            break;
        case ZYDIS_MACHINE_MODE_LONG_COMPAT_16:
        case ZYDIS_MACHINE_MODE_LEGACY_16:
        case ZYDIS_MACHINE_MODE_REAL_16:
            stack_width = ZYDIS_STACK_WIDTH_16;
            break;
        default:
            return ZYAN_STATUS_INVALID_ARGUMENT;
    }

    ZydisDecoder decoder;
    ZYAN_CHECK(ZydisDecoderInit(&decoder, machine_mode, stack_width));

    ZydisDecoderContext ctx;
    ZYAN_CHECK(ZydisDecoderDecodeInstruction(&decoder, &ctx, buffer, length, &instruction->info));
    ZYAN_CHECK(ZydisDecoderDecodeOperands(
        &decoder, &ctx, &instruction->info, instruction->operands, instruction->info.operand_count));

    ZydisFormatter formatter;
    ZYAN_CHECK(ZydisFormatterInit(&formatter, ZYDIS_FORMATTER_STYLE_INTEL));

    default_print_address_absolute = (ZydisFormatterFunc)&UnasmFormatterPrintAddressAbsolute;
    ZydisFormatterSetHook(
        &formatter, ZYDIS_FORMATTER_FUNC_PRINT_ADDRESS_ABS, (const void **)&default_print_address_absolute);

    ZYAN_CHECK(ZydisFormatterFormatInstruction(&formatter,
        &instruction->info,
        instruction->operands,
        instruction->info.operand_count_visible,
        instruction->text,
        sizeof(instruction->text),
        runtime_address,
        user_data));

    return ZYAN_STATUS_SUCCESS;
}
} // namespace

void unassemblize::Function::disassemble()
{
    if (m_executable.section_size(m_section.c_str()) == 0) {
        return;
    }

    ZyanUSize offset = m_startAddress - m_executable.section_address(m_section.c_str());
    uint64_t runtime_address = m_startAddress;
    ZyanUSize end_offset = m_endAddress - m_executable.section_address(m_section.c_str());
    ZydisDisassembledInstruction instruction;

    // Loop through function once to identify all jumps to local labels and create them.
    while (ZYAN_SUCCESS(UnasmDisassembleNoFormat(ZYDIS_MACHINE_MODE_LEGACY_32,
               runtime_address,
               m_executable.section_data(m_section.c_str()) + offset,
               96,
               &instruction))
        && offset < end_offset) {
        if (instruction.info.raw.imm->is_relative) {
            uint64_t address; 
            ZydisCalcAbsoluteAddress(&instruction.info, instruction.operands, runtime_address, &address);

            if (address >= m_startAddress && address <= m_endAddress && m_labels.find(address) == m_labels.end()) {
                std::stringstream stream;
                stream << std::hex << address;
                m_labels[address] = std::string("label_") + stream.str();
            }
        }

        offset += instruction.info.length;
        runtime_address += instruction.info.length;
    }

    offset = m_startAddress - m_executable.section_address(m_section.c_str());
    runtime_address = m_startAddress;

    while (ZYAN_SUCCESS(UnasmDisassembleCustom(ZYDIS_MACHINE_MODE_LEGACY_32,
               runtime_address,
               m_executable.section_data(m_section.c_str()) + offset,
               96,
               &instruction,
               this))
        && offset < end_offset) {
        if (m_labels.find(runtime_address) != m_labels.end()) {
            m_dissassembly += m_labels[runtime_address];
            m_dissassembly += ":\n";
        }

        m_dissassembly += "    ";
        m_dissassembly += instruction.text;
        m_dissassembly += '\n';
        offset += instruction.info.length;
        runtime_address += instruction.info.length;
    }
}
