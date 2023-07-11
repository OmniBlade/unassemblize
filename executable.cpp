#include "executable.h"
#include <LIEF/LIEF.hpp>

unassemblize::Executable::Executable(const char *file_name) : m_binary(LIEF::Parser::parse(file_name))
{
    for (auto it = m_binary->sections().begin(); it != m_binary->sections().end(); ++it) {
        SectionInfo &section = m_sections[it->name()];
        section.data = &it->content()[0];
        section.address = m_binary->imagebase() + it->virtual_address();
        section.size = it->size();
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

uint64_t unassemblize::Executable::size() const
{
    return m_binary->original_size();
}
