pos = 0

Node = {}
Node.__index = Node

function Node:new(name, start, size, value)
  o = {}
  o.children = {}
  o.dir = {}
  o.name = name
  o.start = start
  o.size = size
  o.value = value -- leaf node only
  setmetatable(o, self)
  return o
end

function Node:append_node(child)
  local index = #self.children+1
  self.children[index] = child
  self.dir[child.name] = index
end

function Node:child(name)
  return self.children[self.dir[name]]
end

function Node:field(...)
  local node = self
  for i=1,select('#', ...) do
    node = node:child(select(i, ...))
  end
  return node.value or node
end

function Node:print(depth)
  local indent = (function(d)
    return function()
      io.write(string.rep('  ', d))
    end
  end)(depth)
  if self.value then
    indent()
    typ = type(self.value)
    if typ == 'number' then
      print(string.format('%s = %d (0x%x)', self.name, self.value, self.value))
    elseif typ == 'string' then
      print(string.format('%s = %s', self.name, self.value))
    end
  else
    indent()
    io.write(string.format('%s: %d bytes', self.name, self.size))
    if #self.children > 0 then
      print(' {')
      for i=1, #self.children do
        self.children[i]:print(depth+1)
      end
      indent()
      print('}')
    else
      print()
    end
  end
end

file = assert(io.open(arg[1], 'rb'))

function u8(name)
  local bytes = file:read(1)
  value = string.byte(bytes:sub(1,1))
  current_node:append_node(Node:new(name, pos, 1, value))
  pos = pos+1
end

function u16(name)
  local bytes = file:read(2)
  value = string.byte(bytes:sub(1,1)) | string.byte(bytes:sub(2,2)) << 8
  current_node:append_node(Node:new(name, pos, 2, value))
  pos = pos+2
end

function u32(name)
  local bytes = file:read(4)
  value = string.byte(bytes:sub(1,1)) | string.byte(bytes:sub(2,2)) << 8 | string.byte(bytes:sub(3,3)) << 16 | string.byte(bytes:sub(4,4)) << 24
  current_node:append_node(Node:new(name, pos, 4, value))
  pos = pos+4
end

function u64(name)
  local bytes = file:read(8)
  value =
  string.byte(bytes:sub(1,1))       |
  string.byte(bytes:sub(2,2)) <<  8 |
  string.byte(bytes:sub(3,3)) << 16 |
  string.byte(bytes:sub(4,4)) << 24 |
  string.byte(bytes:sub(5,5)) << 32 |
  string.byte(bytes:sub(6,6)) << 40 |
  string.byte(bytes:sub(7,7)) << 48 |
  string.byte(bytes:sub(8,8)) << 56
  current_node:append_node(Node:new(name, pos, 8, value))
  pos = pos+8
end

function array(proc, n)
  function parse(name)
    local t = Node:new(name, pos)
    local saved_current_node = current_node
    current_node = t
    for i=1,n do
      proc(i)
    end
    current_node = saved_current_node
    t.size = pos - t.start
    current_node:append_node(t)
  end
  return parse
end

function ascii(n)
  function parse(name)
    local bytes = file:read(n)
    current_node:append_node(Node:new(name, pos, n, bytes))
    pos = pos+n
  end
  return parse
end

function map(proc, list)
  function parse(name)
    local t = Node:new(name, pos)
    local saved_current_node = current_node
    current_node = t
    for i=1,#list.children do
      proc(list.children[i])(i)
    end
    current_node = saved_current_node
    t.size = pos - t.start
    current_node:append_node(t)
  end
  return parse
end

function data(n)
  function parse(name)
    file:seek('cur', n)
    current_node:append_node(Node:new(name, pos, n))
    pos = pos+n
  end
  return parse
end

function record(proc)
  function parse(name)
    local t = Node:new(name, pos)
    local saved_current_node = current_node
    current_node = t
    proc(function(...)
      if ... == '.' then
        return pos-t.start
      else
        return t:field(...)
      end
    end)
    current_node = saved_current_node
    t.size = pos - t.start
    if current_node then
      current_node:append_node(t)
    else
      current_node = t
    end
  end
  return parse
end

dos_header = record(function(eval)
  u16('e_magic')
  local magic = eval('e_magic')
  if magic ~= 0x5a4d then
    error(string.format('invalid DOS executable magic: 0x%04x', magic))
  end
  u16('e_cblp')
  u16('e_cp')
  u16('e_crlc')
  u16('e_cparhdr')
  u16('e_minalloc')
  u16('e_maxalloc')
  u16('e_ss')
  u16('e_sp')
  u16('e_csum')
  u16('e_ip')
  u16('e_cs')
  u16('e_lfarlc')
  u16('e_ovno')
  data(8)('e_res')
  u16('e_oemid')
  u16('e_oeminfo')
  data(20)('e_res2')
  u32('e_lfanew')
end)

dos_exe = record(function(eval)
  dos_header('dos_header')
  data( eval('dos_header', 'e_lfanew') - eval('.') )('data')
end)

data_directory = record(function()
  u32('rva')
  u32('size')
end)

optional_header = record(function(eval)
  u16('magic')
  local magic = eval('magic')
  local ispe32plus
  if magic == 0x10b then
    ispe32plus = false
  elseif magic == 0x20b then
    ispe32plus = true
  else
    error(string.format('invalid optional header magic: 0x%04x', magic))
  end
  usize = ispe32plus and u64 or u32
  u8('major_linker_version')
  u8('minor_linker_version')
  u32('code_size')
  u32('data_size')
  u32('bss_size')
  u32('entry_point_address')
  u32('code_base')
  if not ispe32plus then u32('data_base') end
  usize('image_base')
  u32('section_align')
  u32('file_align')
  u16('major_os_version')
  u16('minor_os_version')
  u16('major_image_version')
  u16('minor_image_version')
  u16('major_subsystem_version')
  u16('minor_subsystem_version')
  u32('win32_version_value')
  u32('image_size')
  u32('headers_size')
  u32('checksum')
  u16('subsystem')
  u16('dll_flags')
  usize('stack_size_reserve')
  usize('stack_size_commit')
  usize('heap_size_reserve')
  usize('heap_size_commit')
  u32('loader_flags')
  u32('num_data_directories')
  array(data_directory, eval('num_data_directories'))('data_directories')
end)

pe_header = record(function(eval)
  u32('pe_signature')
  local magic = eval('pe_signature')
  if magic ~= 0x4550 then
    error(string.format('invalid PE signature: 0x%08x', magic))
  end
  u16('machine_type')
  u16('num_sections')
  u32('timestamp')
  u32('symbol_table_offset')
  u32('num_symbols')
  u16('optional_header_size')
  u16('flags')
  optional_header('optional_header')
end)

section_header = record(function()
  ascii(8)('name')
  u32('virtual_size')
  u32('virtual_address')
  u32('raw_data_size')
  u32('raw_data_offset')
  u32('reloc_offset')
  u32('linenum_offset')
  u16('num_reloc')
  u16('num_linenum')
  u32('flags')
end)

section = function(pad_len, data_len)
  return record(function()
    data(pad_len)('pad')
    data(data_len)('data')
  end)
end

pe = record(function(eval)
  dos_exe('dos_exe')
  pe_header('pe_header')
  local num_sections = eval('pe_header', 'num_sections')
  array(section_header, num_sections)('section_headers')
  map(function(h)
    return section(h:field('raw_data_offset')-eval('.'), h:field('raw_data_size'))
  end, eval('section_headers'))('sections')
end)

pe('pe')

current_node:print(0)
