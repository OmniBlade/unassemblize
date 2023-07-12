#include "executable.h"
#include <LIEF/LIEF.hpp>

unassemblize::Executable::Executable(const char *file_name) : m_binary(LIEF::Parser::parse(file_name)), m_endAddress(0)
{
    for (auto it = m_binary->sections().begin(); it != m_binary->sections().end(); ++it) {
        if (!it->name().empty() && it->size() != 0) {
            SectionInfo &section = m_sections[it->name()];
            section.data = it->content().data();

            // For PE format virtual_address appears to be an offset, in ELF/Mach-O it appears to be absolute.
            if (it->virtual_address() > m_binary->imagebase()) {
                section.address = it->virtual_address();
            } else {
                section.address = m_binary->imagebase() + it->virtual_address();
            }

            section.size = it->size();

            if (section.address + section.size > m_endAddress) {
                m_endAddress = section.address + section.size;
            }
        }
    }
}

const uint8_t *unassemblize::Executable::section_data(const char *name) const
{
    auto it = m_sections.find(name);
    return it != m_sections.end() ? it->second.data : nullptr;
}

uint64_t unassemblize::Executable::section_address(const char *name) const
{
    auto it = m_sections.find(name);
    return it != m_sections.end() ? it->second.address : UINT64_MAX;
}

uint64_t unassemblize::Executable::section_size(const char *name) const
{
    auto it = m_sections.find(name);
    return it != m_sections.end() ? it->second.size : 0;
}

uint64_t unassemblize::Executable::base_address() const
{
    return m_binary->imagebase();
}

const std::string &unassemblize::Executable::get_symbol(uint64_t addr) const
{
    static std::string def;

    if (m_symbols.find(addr) != m_symbols.end()) {
        return m_symbols.find(addr)->second;
    }

    return def;
}
