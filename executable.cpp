#include "executable.h"
#include <LIEF/LIEF.hpp>
#include <fstream>
#include <iostream>
#include <nlohmann/json.hpp>

const char unassemblize::Executable::s_symbolSection[] = "symbols";

unassemblize::Executable::Executable(const char *file_name, bool verbose) :
    m_binary(LIEF::Parser::parse(file_name)), m_endAddress(0), m_verbose(verbose)
{
    if (m_verbose) {
        printf("Loading section info...\n");
    }

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

    if (m_verbose) {
        printf("Indexing embedded symbols...\n");
    }

    auto exe_syms = m_binary->symbols();

    for (auto it = exe_syms.begin(); it != exe_syms.end(); ++it) {
        if (it->value() != 0 && !it->name().empty() && m_symbolMap.find(it->value()) == m_symbolMap.end()) {
            m_symbolMap.insert({it->value(), Symbol(it->name(), it->value(), it->size())});
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

const unassemblize::Executable::Symbol &unassemblize::Executable::get_symbol(uint64_t addr) const
{
    static std::string empty;
    static Symbol def(empty, 0, 0);
    auto it = m_symbolMap.lower_bound(addr);

    if (it != m_symbolMap.end()) {
        if (it->second.value == addr) {
            return it->second;
        } else {
            return std::prev(it)->second;
        }
    }

    return def;
}

void unassemblize::Executable::load_symbols(const char *file_name)
{
    std::ifstream fs(file_name);

    if (!fs.good()) {
        return;
    }

    nlohmann::json j = nlohmann::json::parse(fs);
    auto &jsyms = j.at(s_symbolSection);

    for (auto it = jsyms.begin(); it != jsyms.end(); ++it) {
        std::string name;
        it->at("name").get_to(name);

        // Don't try and load an empty symbol.
        if (!name.empty()) {
            uint64_t size = 0;
            uint64_t addr = 0;
            it->at("address").get_to(addr);

            if (addr == 0) {
                continue;
            }

            it->at("size").get_to(size);

            if (size == 0) {
                continue;
            }

            // Only load symbols for addresses we don't have any symbol for yet.
            if (m_symbolMap.find(addr) == m_symbolMap.end()) {
                m_loadedSymbols.push_back(name);
                m_symbolMap.insert({addr, {m_loadedSymbols.back(), addr, size}});
            }
        }
    }
}

void unassemblize::Executable::dump_symbols(const char *file_name)
{
    auto exe_syms = m_binary->symbols();
    nlohmann::json j;

    {
        std::ifstream fs(file_name);

        if (fs.good()) {
            j = nlohmann::json::parse(fs);
        }
    }

    if (m_verbose) {
        printf("Dumping symbols to file '%s'...\n", file_name);
    }

    // Remove symbols if it already exists and repopulate it.
    if (j.find(s_symbolSection) != j.end()) {
        j.erase(s_symbolSection);
    }

    j[s_symbolSection] = nlohmann::json();
    auto &syms = j.at(s_symbolSection);

    for (auto it = exe_syms.begin(); it != exe_syms.end(); ++it) {
        syms.push_back({{"name", it->name()}, {"address", it->value()}, {"size", it->size()}});
    }

    std::ofstream fs(file_name);
    fs << std::setw(4) << j << std::endl;
}
