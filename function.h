/**
 * @file
 *
 * @brief Class encapsulating a single function dissassembly.
 *
 * @copyright Assemblize is free software: you can redistribute it and/or
 *            modify it under the terms of the GNU General Public License
 *            as published by the Free Software Foundation, either version
 *            3 of the License, or (at your option) any later version.
 *            A full copy of the GNU General Public License can be found in
 *            LICENSE
 */
#pragma once

#include "executable.h"
#include <map>
#include <stdint.h>
#include <string>
#include <vector>

namespace unassemblize
{
class Function
{
public:
    enum AsmFormat
    {
        FORMAT_DEFAULT,
        FORMAT_IGAS,
        FORMAT_AGAS,
        FORMAT_MASM,
    };

public:
    Function(Executable &exe, const char *section_name, uint64_t start, uint64_t end) :
        m_section(section_name), m_startAddress(start), m_endAddress(end), m_executable(exe)
    {
    }
    void disassemble(AsmFormat fmt = FORMAT_DEFAULT); // Run the dissassmbly of the function.
    const std::string &dissassembly() const { return m_dissassembly; }
    const std::vector<std::string> &dependencies() const { return m_deps; }
    void add_dependency(const std::string &dep) { return m_deps.push_back(dep); }
    uint64_t start_address() const { return m_startAddress; }
    uint64_t end_address() const { return m_endAddress; }
    uint64_t section_address() const { return m_executable.section_address(m_section.c_str()); }
    uint64_t section_end() const
    {
        return m_executable.section_address(m_section.c_str()) + m_executable.section_size(m_section.c_str());
    }
    const std::map<uint64_t, std::string> &labels() const { return m_labels; }
    const Executable &executable() const { return m_executable; }

private:
    std::map<uint64_t, std::string> m_labels; // Map of labels this function uses internally.
    std::vector<std::string> m_deps; // Symbols this function depends on.
    std::string m_dissassembly; // Dissassembly buffer for this function.
    const std::string m_section;
    const uint64_t m_startAddress; // Runtime start address of the function.
    const uint64_t m_endAddress; // Runtime end address of the function.
    Executable &m_executable;
};
} // namespace unassemblize
