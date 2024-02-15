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

#include <list>
#include <map>
#include <memory>
#include <nlohmann/json_fwd.hpp>
#include <stdio.h>
#include <string>

namespace LIEF
{
class Binary;
}

namespace unassemblize
{
class Executable
{
public:
    enum OutputFormats
    {
        OUTPUT_IGAS,
        OUTPUT_MASM,
    };

    enum SectionTypes
    {
        SECTION_DATA,
        SECTION_CODE,
    };

    struct SectionInfo
    {
        const uint8_t *data;
        uint64_t address;
        uint64_t size;
        SectionTypes type;
    };

    struct Symbol
    {  
        Symbol(std::string &_name, uint64_t _value, uint64_t _size) : name(_name), value(_value), size(_size) {}
        std::string &name;
        uint64_t value;
        uint64_t size;
    };

    struct ObjectSection
    {
        std::string name;
        uint64_t start;
        uint64_t size;
    };

    struct Object
    {
        std::string name;
        std::list<ObjectSection> sections;
    };

public:
    Executable(const char *file_name, OutputFormats format = OUTPUT_IGAS, bool verbose = false);
    const std::map<std::string, SectionInfo> &sections() const { return m_sections; }
    const uint8_t *section_data(const char *name) const;
    uint64_t section_address(const char *name) const;
    uint64_t section_size(const char *name) const;
    uint64_t base_address() const;
    uint64_t end_address() const { return m_endAddress; };
    const Symbol &get_symbol(uint64_t addr) const;
    const Symbol &get_nearest_symbol(uint64_t addr) const;
    void add_symbol(const char *sym, uint64_t addr);
    void load_config(const char *file_name);
    void save_config(const char *file_name);
    /**
     * Dissassembles a range of bytes and outputs the format as though it were a single function.
     * Addresses should be the absolute addresses when the binary is loaded at its preferred base address.
     */
    void dissassemble_function(FILE *output, const char *section_name, uint64_t start, uint64_t end);

private:
    void dissassemble_gas_func(FILE *output, const char *section_name, uint64_t start, uint64_t end);

    void load_symbols(nlohmann::json &js);
    /**
     * Dump symbols from the executable to a config file.
     */
    void dump_symbols(nlohmann::json &js);
    void load_sections(nlohmann::json &js);
    /**
     * Dump sections from the executable to a config file.
     */
    void dump_sections(nlohmann::json &js);
    void load_objects(nlohmann::json &js);
    /**
     * Dump sections from the executable to a config file.
     */
    void dump_objects(nlohmann::json &js);

private:
    std::unique_ptr<LIEF::Binary> m_binary;
    std::map<std::string, SectionInfo> m_sections;
    std::map<uint64_t, Symbol> m_symbolMap;
    std::list<std::string> m_loadedSymbols;
    std::list<Object> m_targetObjects;
    OutputFormats m_outputFormat;
    uint64_t m_endAddress;
    uint32_t m_codeAlignment;
    uint32_t m_dataAlignment;
    uint8_t m_codePad;
    uint8_t m_dataPad;
    bool m_verbose;
    bool m_addBase;

    static const char s_symbolSection[];
    static const char s_sectionsSection[];
    static const char s_configSection[];
    static const char s_objectSection[];
};
}
