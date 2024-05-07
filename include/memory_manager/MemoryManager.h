//
// Created by vlad on 10/29/23.
//

#pragma once
#include <string>
#include <optional>
#include <vector>
#include <cstdint>
#include <any>
#include <sys/uio.h>
namespace memory_manager
{

    class MemoryManager
    {
    public:
        explicit MemoryManager(const std::string& procName);

        [[nodiscard]]
        static std::optional<pid_t> GetProcessIdByName(const std::string& procName);

        [[nodiscard]]
        std::optional<uintptr_t> GetModuleBaseAddressByName(const std::string& moduleName) const;

        [[nodiscard]]
        std::optional<std::pair<uintptr_t,uintptr_t>>
        GetModuleExecutableMemoryRange(const std::string& moduleName) const;
        [[nodiscard]]
        std::optional<uintptr_t> PatternScan(const std::string& moduleName, const std::string& pattern) const;


        [[nodiscard]]
        std::vector<uint8_t> ReadMemory(uintptr_t addr, size_t size) const;

        void WriteMemory(void* buffer, uintptr_t addr, size_t size);

        template<class type>
        void WriteMemory(uintptr_t addr, const type val)
        {
            WriteMemory((void*)&val, addr, sizeof(val));
        }


        template<class type>
        std::optional<type> ReadMemory(uintptr_t addr) const
        {
            type buffer;

            iovec localMemoryRegion{.iov_base = &buffer, .iov_len = sizeof(buffer)};
            iovec remoteMemoryRegion{.iov_base = reinterpret_cast<void*>(addr), .iov_len = sizeof(buffer) };

            const auto readBytes = process_vm_readv(m_procId, &localMemoryRegion, 1, &remoteMemoryRegion, 1, 0);

            return readBytes > 0 ? std::optional(buffer) : std::nullopt;
        }

    private:
        pid_t m_procId;
    };
} // memory_manager
