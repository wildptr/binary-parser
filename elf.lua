local P = {} -- this package

local bp = require('binary_parser')

function P.parse(file)

  bp.new(file)()

  local Elf_Ehdr = record(function()
    local magic = u32 'EI_MAG'
    if magic ~= 0x464c457f then
      error('invalid ELF magic')
    end
    local class = u8 'EI_CLASS'
    local usize
    if class == 1 then
      usize = u32
    elseif class == 2 then
      usize = u64
    else
      error('invalid EI_CLASS value')
    end
    u8 'EI_DATA'
    u8 'EI_VERSION'
    u8 'EI_OSABI'
    u8 'EI_ABIVERSION'
    data(7) 'EI_PAD'
    u16 'e_type'
    u16 'e_machine'
    u32 'e_version'
    usize 'e_entry'
    usize 'e_phoff'
    usize 'e_shoff'
    u32 'e_flags'
    u16 'e_ehsize'
    u16 'e_phentsize'
    u16 'e_phnum'
    u16 'e_shentsize'
    u16 'e_shnum'
    u16 'e_shstrndx'
  end)

  local Elf32_Phdr = record(function()
    u32 'p_type'
    u32 'p_offset'
    u32 'p_vaddr'
    u32 'p_paddr'
    u32 'p_filesz'
    u32 'p_memsz'
    u32 'p_flags'
    u64 'p_align'
  end)

  local Elf64_Phdr = record(function()
    u32 'p_type'
    u32 'p_flags'
    u64 'p_offset'
    u64 'p_vaddr'
    u64 'p_paddr'
    u64 'p_filesz'
    u64 'p_memsz'
    u64 'p_align'
  end)

  local Elf32_Shdr = record(function()
    u32 'sh_name'
    u32 'sh_type'
    u32 'sh_flags'
    u32 'sh_addr'
    u32 'sh_offset'
    u32 'sh_size'
    u32 'sh_link'
    u32 'sh_info'
    u32 'sh_addralign'
    u32 'sh_entsize'
  end)

  local Elf64_Shdr = record(function()
    u32 'sh_name'
    u32 'sh_type'
    u64 'sh_flags'
    u64 'sh_addr'
    u64 'sh_offset'
    u64 'sh_size'
    u32 'sh_link'
    u32 'sh_info'
    u64 'sh_addralign'
    u64 'sh_entsize'
  end)

  local elf = record(function(this)
    local elf_header = Elf_Ehdr 'elf_header'
    local is64 = elf_header'EI_CLASS' == 2
    local phoff = elf_header'e_phoff'
    if phoff ~= 0 then
      local phdr = is64 and Elf64_Phdr or Elf32_Phdr
      data(phoff-this'.') 'pad_phdr'
      array(phdr, elf_header'e_phnum') 'program_headers'
    end
    local shoff = elf_header'e_shoff'
    if shoff ~= 0 then
      local shdr = is64 and Elf64_Shdr or Elf32_Shdr
      data(shoff-this'.') 'pad_shdr'
      array(shdr, elf_header'e_shnum') 'section_headers'
    end
  end)

  return elf 'elf'
end

return P
