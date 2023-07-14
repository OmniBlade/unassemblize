/**
 * @file
 *
 * @brief Class encapsulating the executable being dissassembled.
 *
 * @copyright Assemblize is free software: you can redistribute it and/or
 *            modify it under the terms of the GNU General Public License
 *            as published by the Free Software Foundation, either version
 *            3 of the License, or (at your option) any later version.
 *            A full copy of the GNU General Public License can be found in
 *            LICENSE
 */
#pragma once

#include <map>
#include <memory>
#include <string>
#include <vector>

namespace LIEF
{
class Binary;
}

namespace unassemblize
{
class Executable
{
public:
    struct SectionInfo
    {
        const uint8_t *data;
        uint64_t address;
        uint64_t size;
    };

    struct Symbol
    {  
        Symbol(std::string &_name, uint64_t _value, uint64_t _size) : name(_name), value(_value), size(_size) {}
        std::string &name;
        uint64_t value;
        uint64_t size;
    };

public:
    Executable(const char *file_name, bool verbose = false);
    const std::map<std::string, SectionInfo> &sections() const { return m_sections; }
    const uint8_t *section_data(const char *name) const;
    uint64_t section_address(const char *name) const;
    uint64_t section_size(const char *name) const;
    uint64_t base_address() const;
    uint64_t end_address() const { return m_endAddress; };
    const Symbol &get_symbol(uint64_t addr) const;
    void load_symbols(const char *file_name);
    /**
     * Dump symbols from the executable.
     */
    void dump_symbols(const char *file_name);

private:
    std::unique_ptr<LIEF::Binary> m_binary;
    std::map<std::string, SectionInfo> m_sections;
    std::map<uint64_t, Symbol> m_symbolMap;
    std::vector<std::string> m_loadedSymbols;
    uint64_t m_endAddress;
    bool m_verbose;

    static const char s_symbolSection[];
};
}
